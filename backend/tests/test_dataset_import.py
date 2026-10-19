"""Tests for the external dataset import interface (Day 8).

All inputs here are tiny synthetic CSVs written to a temp directory. No dataset
is downloaded and no URL is ever resolved or fetched.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from eval import evaluator
from eval import import_dataset as di


PHISHTANK_CSV = """\
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
2001,https://secure-login.example.test/auth,http://www.phishtank.com/phish_detail.php?phish_id=2001,2026-10-01T09:00:00+00:00,yes,2026-10-01T09:05:00+00:00,yes,Example Bank
2002,https://secure-login.example.test/auth,http://www.phishtank.com/phish_detail.php?phish_id=2002,2026-10-03T09:00:00+00:00,yes,2026-10-03T09:05:00+00:00,yes,Example Bank
2003,,http://www.phishtank.com/phish_detail.php?phish_id=2003,2026-10-02T09:00:00+00:00,yes,2026-10-02T09:05:00+00:00,yes,Missing URL
2004,http://mailbox.example.test/verify,http://www.phishtank.com/phish_detail.php?phish_id=2004,2026-10-05T09:00:00+00:00,yes,2026-10-05T09:05:00+00:00,yes,Mail Host
"""

TRANCO_CSV = """\
1,example.test
2,example.com
3,www.example.test
badrow-without-a-domain
4,not a domain
5,http://evil.example.test/path
6,example.test
"""


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


# --- phishtank -------------------------------------------------------------

def test_phishtank_import_labels_and_dedupes(tmp_path):
    path = _write(tmp_path, "pt.csv", PHISHTANK_CSV)
    rows, counts = di.read_phishtank(path)

    assert counts["rows_read"] == 4
    assert counts["written"] == 2
    assert counts["duplicates"] == 1
    assert counts["skipped_empty_url"] == 1
    assert [r["label"] for r in rows] == ["suspicious", "suspicious"]
    assert rows[0]["source"] == "phishtank"
    assert rows[0]["phish_id"] == "2001"
    assert rows[0]["submission_time"].startswith("2026-10-01")
    assert rows[0]["target"] == "Example Bank"
    # URL strings preserved verbatim, never normalised into a fetch
    assert rows[0]["url"] == "https://secure-login.example.test/auth"


def test_phishtank_since_filter(tmp_path):
    path = _write(tmp_path, "pt.csv", PHISHTANK_CSV)
    rows, counts = di.read_phishtank(path, since=di.parse_since("2026-10-04"))
    assert [r["phish_id"] for r in rows] == ["2004"]
    assert counts["skipped_before_since"] == 2  # 2001 + 2002 (2003 is empty-url)
    assert counts["written"] == 1


def test_phishtank_limit(tmp_path):
    path = _write(tmp_path, "pt.csv", PHISHTANK_CSV)
    rows, _ = di.read_phishtank(path, limit=1)
    assert len(rows) == 1


def test_phishtank_missing_columns_raises(tmp_path):
    path = _write(tmp_path, "bad.csv", "url,label\nhttps://a.test/,suspicious\n")
    with pytest.raises(di.DatasetError, match="missing PhishTank columns"):
        di.read_phishtank(path)


def test_phishtank_missing_file_raises(tmp_path):
    with pytest.raises(di.DatasetError, match="not found"):
        di.read_phishtank(tmp_path / "nope.csv")


def test_bad_since_value_raises():
    with pytest.raises(di.DatasetError, match="--since"):
        di.parse_since("not-a-date")


# --- tranco ----------------------------------------------------------------

def test_tranco_import_builds_https_urls(tmp_path):
    path = _write(tmp_path, "tranco.csv", TRANCO_CSV)
    rows, counts = di.read_tranco(path)

    assert counts["written"] == 3
    assert counts["skipped_malformed"] == 3  # no-domain, whitespace, scheme+path
    assert counts["duplicates"] == 1
    assert [r["url"] for r in rows] == [
        "https://example.test/",
        "https://example.com/",
        "https://www.example.test/",
    ]
    assert all(r["label"] == "legit" for r in rows)
    assert [r["rank"] for r in rows] == [1, 2, 3]
    assert rows[0]["source"] == "tranco"


def test_tranco_limit(tmp_path):
    path = _write(tmp_path, "tranco.csv", TRANCO_CSV)
    rows, _ = di.read_tranco(path, limit=2)
    assert len(rows) == 2


def test_tranco_header_line_is_skipped(tmp_path):
    path = _write(tmp_path, "tranco.csv", "rank,domain\n1,example.test\n")
    rows, counts = di.read_tranco(path)
    assert counts["rows_read"] == 1
    assert rows[0]["rank"] == 1


@pytest.mark.parametrize(
    "domain",
    ["", "nodots", "has space.test", "http://x.test", "a.test/path", ".lead.test",
     "trail.test.", "user@x.test", "x.test:8080"],
)
def test_valid_domain_rejects_non_domains(domain):
    assert di.valid_domain(domain) is False


def test_valid_domain_accepts_plain_and_punycode():
    assert di.valid_domain("example.test") is True
    assert di.valid_domain("sub.example.co.uk") is True
    assert di.valid_domain("xn--p1ai.example") is True


# --- write / merge / round-trip -------------------------------------------

def test_write_dataset_creates_jsonl_and_sidecar(tmp_path):
    rows, counts = di.read_phishtank(_write(tmp_path, "pt.csv", PHISHTANK_CSV))
    out = tmp_path / "out" / "phishtank.jsonl"
    sidecar = di.write_dataset(
        rows,
        out,
        meta={
            "source": "phishtank",
            "source_url": di.PHISHTANK_SOURCE_URL,
            "source_licence_note": di.PHISHTANK_LICENCE_NOTE,
            "input_file": "pt.csv",
            "counts": counts,
        },
    )
    assert out.is_file()
    assert sidecar.is_file()
    assert sidecar.name == "phishtank.jsonl.meta.json"

    import json

    meta = json.loads(sidecar.read_text(encoding="utf-8"))
    assert meta["output_rows"] == 2
    assert meta["output_sha256"] == di.sha256_file(out)
    assert meta["imported_utc"]
    assert "never fetched" in meta["note"]
    # Licence note must carry both the operator's permitted-use statement and
    # the honest caveat that no formal licence text was found.
    assert "PhishTank" in meta["source_licence_note"]
    assert "No formal CC-style licence text" in meta["source_licence_note"]


def test_merged_dataset_loads_in_evaluator(tmp_path):
    pt_rows, _ = di.read_phishtank(_write(tmp_path, "pt.csv", PHISHTANK_CSV))
    tr_rows, _ = di.read_tranco(_write(tmp_path, "tranco.csv", TRANCO_CSV))

    a = tmp_path / "phishtank.jsonl"
    b = tmp_path / "tranco.jsonl"
    di.write_dataset(pt_rows, a, meta={"source": "phishtank"})
    di.write_dataset(tr_rows, b, meta={"source": "tranco"})

    merged, counts = di.merge_files([a, b])
    assert counts["written"] == 5  # 2 suspicious + 3 legit
    assert {r["label"] for r in merged} == {"suspicious", "legit"}

    merged_path = tmp_path / "eval-dataset.jsonl"
    di.write_dataset(merged, merged_path, meta={"source": "merge"})

    # Round-trips through the existing evaluator unchanged.
    examples = evaluator.load_fixtures(merged_path)
    assert len(examples) == 5
    metrics, rows = evaluator.evaluate(examples)
    assert metrics["total"] == 5
    assert len(rows) == 5


def test_merge_dedupes_first_wins(tmp_path):
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    di.write_dataset([{"url": "https://x.test/", "label": "legit", "source": "tranco"}],
                     a, meta={"source": "tranco"})
    di.write_dataset([{"url": "https://x.test/", "label": "suspicious", "source": "phishtank"}],
                     b, meta={"source": "phishtank"})
    rows, counts = di.merge_files([a, b])
    assert counts["duplicates"] == 1
    assert len(rows) == 1
    assert rows[0]["source"] == "tranco"


# --- safety ----------------------------------------------------------------

def test_importer_contains_no_network_code():
    """The import tool must never fetch, resolve or submit dataset URLs."""
    src = Path(di.__file__).read_text(encoding="utf-8")
    banned = (
        "import httpx",
        "import requests",
        "urllib.request",
        "import socket",
        "from socket",
        "import aiohttp",
        "http.client",
        "subprocess",
    )
    for needle in banned:
        assert needle not in src, f"network-capable import found: {needle}"
    # and it must not call out to the analyzer either (analysis is a separate step)
    assert "analyze_url" not in src
