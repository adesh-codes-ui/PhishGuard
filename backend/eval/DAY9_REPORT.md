# Day 9: First Real-Data Evaluation — BLOCKED ON LOCAL DATA

**Status: no valid real-data evaluation was performed.** No real dataset exists
in the repository or under the ignored `backend/eval/data/` directory, so there
are **no real-data metrics** in this report. Nothing was fabricated, no download
was claimed, and no dataset access control was bypassed.

Compliance with the Day 9 rules:

- Production thresholds (Low 0-24 / Medium 25-49 / High 50-74 / Critical 75-100)
  unchanged, in `app/analyzer.py:339-345`.
- No analyzer rule, scoring weight, API or frontend behavior changed (only this
  report file was added).
- No dataset URL was visited, resolved, crawled or submitted; URLs remain strings.

## 1. Sources and tooling inspected (as required, before anything else)

- `eval/DATASETS.md` — Day 8 licence/provenance notes and manual acquisition steps.
- `eval/import_dataset.py` — `phishtank` / `tranco` / `merge` subcommands; validates
  the documented PhishTank header, `--limit`/`--since`, de-duplicates, writes
  evaluator-compatible JSONL plus a `.jsonl.meta.json` provenance sidecar
  (source URL, licence note, input SHA-256, row counts, import time). No network code.
- `eval/evaluator.py` — `--fixtures PATH` (default still the 12-row synthetic
  `fixtures.jsonl`); positive class = High/Critical; prints confusion matrix,
  accuracy, precision, recall, specificity, F1.

## 2. Dataset availability check (actual evidence)

```
backend/eval/data/                    -> does not exist
repo-wide search for *.csv *.gz *.zip *.bz2 *.jsonl (excluding node_modules,
.venv, dist, __pycache__)             -> only backend/eval/fixtures.jsonl (834 B)
```

Result: **one local dataset only, and it is the synthetic fixture set**
(12 constructed rows, 6 suspicious / 6 legitimate). Per the Day 9 instructions
the synthetic set must not be mixed into real-data metrics, and it cannot stand in
for them. Therefore Task 4 (inspection/import of real data), Task 5 (metrics) and
Task 6 (partial single-class metrics) have **no valid inputs yet**.

## 3. Exact manual acquisition steps

Credentials are needed for only one of the two sources. Place the files in
`backend/eval/data/` (the importer creates the directory; it is gitignored).

### 3a. PhishTank — suspicious class (requires free credentials)

1. Register at <https://www.phishtank.com/register.php> with a username, a valid
   email address and a password; confirm the email (this is what makes the
   application key available, per `faq.php`).
2. Sign in and open the API page (`/api.php` via "My Account"/API) to read the
   application key.
3. Download with a **descriptive User-Agent** (required; the developer page says
   generic/blank agents may be rate-limited or redirected). Keyed form:

   ```bat
   curl -A "phisguard-eval/0.1 (research; contact you@example.org)" ^
     -o backend\eval\data\online-valid.csv.bz2 ^
     "http://data.phishtank.com/data/<KEY>/online-valid.csv.bz2"
   ```

   Keyless form `.../data/online-valid.csv.bz2` is allowed but
   **limited to a few downloads per day**; if it fails, use the key. Do not
   attempt workarounds — the rate limit is the access control.

4. Formats available (from `developer_info.php`): `online-valid.csv`,
   `.csv.gz`, `.csv.bz2`, plus XML / JSON / PHP-serialized variants of the same
   fields. Prefer plain `.csv` if your daily quota allows, else `.bz2`.
5. Expected columns:
   `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`.
   `submission_time`/`verification_time` are ISO-8601 (provenance per row).
6. Decompress to `backend/eval/data/phishtank-online-valid.csv` if needed:

   ```bat
   .venv\Scripts\python.exe -c "import bz2,shutil,sys; shutil.copyfileobj(bz2.open(sys.argv[1],'rb'), open(sys.argv[2],'wb'))" backend\eval\data\online-valid.csv.bz2 backend\eval\data\phishtank-online-valid.csv
   ```

Licensing caveats (unchanged from Day 8 verification):
- FAQ states the data is free via website and API and that use is OK for
  **commercial and non-commercial** purposes; PhishTank is operated by Cisco Talos.
- **No formal CC-style licence text was found** on the pages fetched (the footer
  "Terms of Use" link did not render a separate data-licence page). Treat this as
  operator-permitted use **with attribution to PhishTank/Cisco Talos**, and
  re-check before redistributing the file.
- Do not commit the file: `backend/eval/data/` is gitignored.

### 3b. Tranco — legitimate class (no credentials)

1. Open <https://tranco-list.eu/> → **Download** (or "Retrieve latest list").
   Note and record the **list ID and date** shown for reproducibility.
2. Save the zip under `backend/eval/data/` and extract the CSV to
   `backend/eval/data/tranco-top-1m.csv`.
3. Format: Alexa/Umbrella style `rank,domain` (no header in the classic Alexa
   layout; the importer tolerates both), one entry per line, no scheme.
4. Provenance: permanent citable list IDs; a daily list published by 0:00 UTC —
   the `Last-Modified` response header gives the exact snapshot time.

Licensing/label caveats:
- Provider licences stated on tranco-list.eu: Cisco Umbrella (free of charge),
  Majestic (**CC BY 3.0**), CrUX (**CC BY-SA 4.0**), Cloudflare Radar
  (**CC BY-NC 4.0**), plus Farsight for the default list. The CC BY-NC component
  matters for commercial use.
- Tranco's own terms page is still unverified (`/about` returned 404).
- **Popularity rank ≠ benign.** Tranco applies Google Safe Browsing filtering,
  which removes known-malicious sites, but a popular domain can still be
  compromised. The "legit" label here means *not known-malicious at snapshot
  time*, not *verified harmless*.

## 4. What will be checked and reported once files are present

Files in place → run (§5) → report: sample counts per class, exact paths and
`.meta.json` provenance (source URL, licence note, input SHA-256, import time),
deduplication counts, missing/malformed rows, class balance and sampling caveats
(no stratification: limits are head-of-file, i.e. most recent phishing rows /
top-ranked domains), confusion matrix TP/FN/FP/TN, precision, recall, specificity,
accuracy, F1 and FPR.

If only one class materialises, only the metrics valid for that class will be
reported (e.g. no precision/recall/F1 without both classes) — correctness over
completeness.

## 5. Reproducible commands (offline, URL-as-string)

```bat
cd backend
.venv\Scripts\python.exe eval\import_dataset.py phishtank eval\data\phishtank-online-valid.csv --limit 1000 --since 2026-09-01 --out eval\data\phishtank.jsonl
.venv\Scripts\python.exe eval\import_dataset.py tranco    eval\data\tranco-top-1m.csv       --limit 1000                --out eval\data\tranco.jsonl
.venv\Scripts\python.exe eval\import_dataset.py merge eval\data\phishtank.jsonl eval\data\tranco.jsonl --out eval\data\eval-dataset.jsonl
.venv\Scripts\python.exe eval\evaluator.py --fixtures eval\data\eval-dataset.jsonl
```

Adjust `--since`/`--limit` deliberately and quote them with the results.

### Tooling readiness (NOT results)

Verified today that the pipeline works end-to-end by pointing the importer and
evaluator at synthetic-shaped files in
`%LOCALAPPDATA%\Temp\opencode\phisguard-day9-dryrun` (temp only, outside the
repo, deleted-able; nothing copied into `eval/`):

- importer de-duplicated (3 rows read → 2 written, `duplicates=1`) and skipped
  nothing on a clean Tranco-shaped sample (`written=3`, `skipped_malformed=0`);
- `merge` produced 5 rows; `evaluator.py --fixtures` exited 0 and printed the
  external-data LIMITATIONS footer;
- a `.meta.json` sidecar was written with `input_sha256`, counts and import time.

These numbers are a plumbing check on adversary-shaped rows, **not** real-data
results about PhishGuard's heuristics, and must not be quoted as such.

## 6. Test and build results

- Backend (canonical `.venv`, same code): **195 passed, 1 warning, 0 failures**
  (the warning is Starlette's `httpx`/`httpx2` deprecation notice).
- Frontend production build: **succeeded** (`tsc -b && vite build`, 35 modules,
  `index-*.js` 278.50 kB).

## 7. Files changed

- `backend/eval/DAY9_REPORT.md` — this file (new).
- Nothing else: no dataset was downloaded, no source/analyzer/threshold/API/UI
  change was made.

## 8. What is needed to continue

1. A human-acquired `backend/eval/data/phishtank-online-valid.csv` (free API key,
   descriptive User-Agent) and `backend/eval/data/tranco-top-1m.csv` with the list
   ID/date recorded — see §3.
2. Then Day 9's evaluation can run with §5 commands; record the sidecar checksums
   and the noted filters alongside any metrics.
3. Licence check before any redistribution of either file; `.gitignore` already
   prevents committing them.
