#!/usr/bin/env python3
"""Import externally labelled URL datasets for offline PhishGuard evaluation.

Day 8 ("better dataset and detection validation") support tool.

Safety contract
---------------
* Dataset rows are treated as opaque strings. This module never resolves DNS,
  opens sockets, issues HTTP requests, or hands a dataset URL to any remote
  service. The only inputs are local CSV files that a human downloaded
  following ``eval/DATASETS.md``.
* Raw downloads and imported JSONL live in ``eval/data/`` (gitignored) and are
  never committed.

Supported commands
------------------
phishtank  PhishTank/Cisco Talos ``online-valid`` CSV -> label "suspicious"
tranco     Tranco top-sites CSV (``rank,domain``, Alexa style) -> label "legit"
merge      concatenate imported JSONL files, de-duplicating by URL

Output rows are JSON objects compatible with ``eval.evaluator.load_fixtures``
(``url`` + ``label``) plus provenance fields. A ``<output>.jsonl.meta.json``
sidecar records source, licence note, input checksum, row counts and import
time.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

if __package__ is None:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

EVAL_DIR = Path(__file__).resolve().parent
DATA_DIR = EVAL_DIR / "data"

# Documented CSV header on https://www.phishtank.com/developer_info.php
PHISHTANK_COLUMNS_REQUIRED = (
    "phish_id",
    "url",
    "submission_time",
    "verification_time",
    "verified",
    "online",
)
PHISHTANK_SOURCE_URL = "http://data.phishtank.com/data/online-valid.csv.bz2"
PHISHTANK_LICENCE_NOTE = (
    "PhishTank (operated by Cisco Talos): FAQ states the data is free via website "
    "and API and that API use is OK for commercial and non-commercial uses "
    "(checked 2026-10-19 at phishtank.com/faq.php). No formal CC-style licence text "
    "was located on the pages fetched; attribute PhishTank/Cisco Talos and re-check "
    "terms before redistribution."
)
TRANCO_SOURCE_URL = "https://tranco-list.eu/"
TRANCO_LICENCE_NOTE = (
    "Tranco research ranking (checked 2026-10-19 at tranco-list.eu). Provider "
    "licences listed there: Cisco Umbrella free of charge, Majestic CC BY 3.0, "
    "CrUX CC BY-SA 4.0, Cloudflare Radar CC BY-NC 4.0 (non-commercial caveat), "
    "plus Farsight for the default list. Cite the Tranco paper when using the list."
)

# RFC-1123-ish domain syntax, ASCII/punycode only (matches Alexa-style lists).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)$"
)

NO_NETWORK_NOTE = (
    "URLs are treated as strings only: never fetched, resolved or submitted by "
    "PhishGuard tooling."
)


class DatasetError(ValueError):
    """Raised when an input file does not match the documented source format."""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _parse_iso(value: str) -> Optional[datetime]:
    """Parse an ISO-8601 timestamp, assuming UTC when no offset is given."""
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def parse_since(value: str) -> datetime:
    """Parse a user-supplied ``--since`` bound (date or datetime), UTC if naive."""
    parsed = _parse_iso(value)
    if parsed is None:
        raise DatasetError(
            f"--since {value!r} is not an ISO-8601 date/datetime (e.g. 2026-10-01)"
        )
    return parsed


def valid_domain(domain: str) -> bool:
    """True when a bare domain (no scheme/path/port) looks well-formed."""
    if not domain or len(domain) > 253:
        return False
    if any(ch.isspace() for ch in domain):
        return False
    if any(ch in domain for ch in ":/?#@[]"):
        return False
    return bool(_DOMAIN_RE.match(domain))


def _open_csv(path: Path) -> csv.DictReader:
    if not path.is_file():
        raise DatasetError(f"input file not found: {path}")
    handle = path.open("r", encoding="utf-8-sig", errors="replace", newline="")
    return csv.DictReader(handle)


def write_dataset(
    rows: Sequence[Dict],
    out_path: Path,
    meta: Dict,
) -> Path:
    """Write JSONL plus a ``.meta.json`` provenance sidecar; return sidecar path."""
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")

    sidecar = Path(str(out_path) + ".meta.json")
    payload = dict(meta)
    payload.update(
        {
            "output": out_path.name,
            "output_rows": len(rows),
            "output_sha256": sha256_file(out_path),
            "imported_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "note": NO_NETWORK_NOTE,
        }
    )
    sidecar.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8")
    return sidecar


def load_jsonl(path: Path) -> List[Dict]:
    if not path.is_file():
        raise DatasetError(f"input file not found: {path}")
    rows: List[Dict] = []
    with path.open("r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{path.name}:{lineno}: invalid JSON ({exc})") from exc
            if not isinstance(obj, dict) or "url" not in obj or "label" not in obj:
                raise DatasetError(
                    f"{path.name}:{lineno}: rows must be objects with url and label"
                )
            rows.append(obj)
    return rows


# --------------------------------------------------------------------------
# source readers
# --------------------------------------------------------------------------

def read_phishtank(
    path: Path,
    *,
    since: Optional[datetime] = None,
    limit: Optional[int] = None,
) -> Tuple[List[Dict], Dict]:
    """Read a PhishTank online-valid CSV into suspicious-labelled rows."""
    path = Path(path)
    reader = _open_csv(path)
    fieldnames = reader.fieldnames
    if not fieldnames:
        raise DatasetError(f"{path.name}: empty or headerless CSV (expected PhishTank header)")
    missing = [col for col in PHISHTANK_COLUMNS_REQUIRED if col not in fieldnames]
    if missing:
        raise DatasetError(
            f"{path.name}: missing PhishTank columns {missing}; found {list(fieldnames)}"
        )

    counts = {
        "rows_read": 0,
        "written": 0,
        "skipped_empty_url": 0,
        "skipped_not_verified": 0,
        "skipped_before_since": 0,
        "skipped_unparsable_time": 0,
        "duplicates": 0,
    }
    seen = set()
    rows: List[Dict] = []

    for row in reader:
        counts["rows_read"] += 1
        url = (row.get("url") or "").strip()
        if not url:
            counts["skipped_empty_url"] += 1
            continue
        if (row.get("verified") or "").strip().lower() == "no":
            counts["skipped_not_verified"] += 1
            continue
        if since is not None:
            submitted = _parse_iso(row.get("submission_time") or "")
            if submitted is None:
                counts["skipped_unparsable_time"] += 1
                continue
            if submitted < since:
                counts["skipped_before_since"] += 1
                continue
        if url in seen:
            counts["duplicates"] += 1
            continue
        seen.add(url)

        rows.append(
            {
                "url": url,
                "label": "suspicious",
                "source": "phishtank",
                "phish_id": (row.get("phish_id") or "").strip(),
                "submission_time": (row.get("submission_time") or "").strip(),
                "verification_time": (row.get("verification_time") or "").strip(),
                "target": (row.get("target") or "").strip(),
            }
        )
        counts["written"] += 1
        if limit is not None and len(rows) >= limit:
            break

    return rows, counts


def read_tranco(path: Path, *, limit: Optional[int] = None) -> Tuple[List[Dict], Dict]:
    """Read an Alexa-style Tranco CSV (``rank,domain``) into legit-labelled rows."""
    path = Path(path)
    if not path.is_file():
        raise DatasetError(f"input file not found: {path}")

    counts = {
        "rows_read": 0,
        "written": 0,
        "skipped_malformed": 0,
        "duplicates": 0,
    }
    seen = set()
    rows: List[Dict] = []

    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as handle:
        for fields in csv.reader(handle):
            if not fields or not any(field.strip() for field in fields):
                continue
            first = fields[0].strip().lower()
            if first in ("rank", "#rank", "id"):  # optional header line
                continue
            counts["rows_read"] += 1
            try:
                rank = int(fields[0].strip())
            except (ValueError, IndexError):
                counts["skipped_malformed"] += 1
                continue
            domain = fields[1].strip().lower() if len(fields) > 1 else ""
            if not valid_domain(domain):
                counts["skipped_malformed"] += 1
                continue
            url = f"https://{domain}/"
            if url in seen:
                counts["duplicates"] += 1
                continue
            seen.add(url)

            rows.append(
                {
                    "url": url,
                    "label": "legit",
                    "source": "tranco",
                    "rank": rank,
                    "domain": domain,
                }
            )
            counts["written"] += 1
            if limit is not None and len(rows) >= limit:
                break

    return rows, counts


def merge_files(paths: Sequence[Path]) -> Tuple[List[Dict], Dict]:
    """Concatenate JSONL dataset files, keeping the first row for each URL."""
    counts = {"input_files": 0, "rows_read": 0, "written": 0, "duplicates": 0}
    seen = set()
    rows: List[Dict] = []
    for path in paths:
        counts["input_files"] += 1
        for row in load_jsonl(Path(path)):
            counts["rows_read"] += 1
            url = row["url"]
            if url in seen:
                counts["duplicates"] += 1
                continue
            seen.add(url)
            rows.append(row)
            counts["written"] += 1
    return rows, counts


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _summary(label: str, counts: Dict, out_path: Path, sidecar: Path) -> None:
    print(f"[{label}] " + " ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"  wrote {counts.get('written', 0)} rows -> {out_path}")
    print(f"  provenance -> {sidecar}")
    print(f"  {NO_NETWORK_NOTE}")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="import_dataset",
        description="Import labelled URL datasets for offline evaluation "
        "(strings only, no network access).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    pt = sub.add_parser("phishtank", help="PhishTank online-valid CSV -> label 'suspicious'")
    pt.add_argument("input", type=Path, help="downloaded online-valid.csv (see DATASETS.md)")
    pt.add_argument("--out", type=Path, default=DATA_DIR / "phishtank.jsonl")
    pt.add_argument("--limit", type=int, default=None, help="stop after N rows")
    pt.add_argument("--since", default=None,
                    help="ISO date/datetime; keep rows with submission_time >= this")

    tr = sub.add_parser("tranco", help="Tranco 'rank,domain' CSV -> label 'legit'")
    tr.add_argument("input", type=Path)
    tr.add_argument("--out", type=Path, default=DATA_DIR / "tranco.jsonl")
    tr.add_argument("--limit", type=int, default=None, help="stop after N rows")

    mg = sub.add_parser("merge", help="merge imported JSONL files, de-duplicating URLs")
    mg.add_argument("inputs", type=Path, nargs="+")
    mg.add_argument("--out", type=Path, default=DATA_DIR / "eval-dataset.jsonl")

    args = parser.parse_args(argv)

    try:
        if args.command == "phishtank":
            since = parse_since(args.since) if args.since else None
            rows, counts = read_phishtank(args.input, since=since, limit=args.limit)
            meta = {
                "source": "phishtank",
                "source_url": PHISHTANK_SOURCE_URL,
                "source_licence_note": PHISHTANK_LICENCE_NOTE,
                "input_file": args.input.name,
                "input_sha256": sha256_file(args.input),
                "label": "suspicious",
                "filters": {"since": args.since, "limit": args.limit},
                "counts": counts,
            }
            sidecar = write_dataset(rows, args.out, meta)
            _summary("phishtank", counts, args.out, sidecar)

        elif args.command == "tranco":
            rows, counts = read_tranco(args.input, limit=args.limit)
            meta = {
                "source": "tranco",
                "source_url": TRANCO_SOURCE_URL,
                "source_licence_note": TRANCO_LICENCE_NOTE,
                "input_file": args.input.name,
                "input_sha256": sha256_file(args.input),
                "label": "legit",
                "filters": {"limit": args.limit},
                "counts": counts,
            }
            sidecar = write_dataset(rows, args.out, meta)
            _summary("tranco", counts, args.out, sidecar)

        else:  # merge
            rows, counts = merge_files(args.inputs)
            meta = {
                "source": "merge",
                "source_url": None,
                "source_licence_note": "Inherited from each input's .meta.json sidecar.",
                "input_files": [p.name for p in args.inputs],
                "inputs_sha256": {p.name: sha256_file(p) for p in args.inputs},
                "counts": counts,
            }
            sidecar = write_dataset(rows, args.out, meta)
            _summary("merge", counts, args.out, sidecar)

    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
