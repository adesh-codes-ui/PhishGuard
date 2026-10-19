# External datasets for offline evaluation (Day 8)

Where PhishGuard's offline evaluation data comes from, how to acquire it, and
what is (and is not) verified about it.

Raw downloads and imported JSONL go in `eval/data/`, which is **gitignored**.
Never commit dataset files.

## Hard rules

1. Dataset URLs are **strings only**. Nothing in this repo visits, resolves,
   opens or submits a dataset URL. `eval/import_dataset.py` contains no network
   code, and a test (`test_importer_contains_no_network_code`) enforces that.
2. Do not claim a dataset is downloaded or verified unless the file, its source
   and its licence were actually checked. Per-source status is recorded below
   and must be updated honestly.
3. Imported datasets are for **evaluation only**. Do not tune heuristic weights
   or production bands (Low 0-24 / Medium 25-49 / High 50-74 / Critical 75-100)
   on data you intend to report as held-out.

## Status of the two sources (checked 19 Oct 2026)

| Class | Source | File acquired? | Licence verified? |
|---|---|---|---|
| suspicious | PhishTank `online-valid` CSV | **No** — not downloaded | Usage statement verified, no formal CC licence found |
| legit | Tranco top-sites list | **No** — not downloaded | Provider licences verified on tranco-list.eu |

Both official pages were fetched and read; the data files themselves were not.

## Source 1 — PhishTank verified phishing URLs (positive class)

- Operator: PhishTank, operated by Cisco Talos Intelligence Group.
- Official pages read on 19 Oct 2026:
  - <https://www.phishtank.com/faq.php>
  - <https://www.phishtank.com/developer_info.php>

**Verified from those pages**

- Bulk dumps: `http://data.phishtank.com/data/online-valid.csv` (also `.gz`,
  `.bz2`; XML/JSON/PHP variants exist), updated hourly.
- Documented CSV header:
  `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`
  — ISO-8601 timestamps give per-row provenance (submission + verification).
- Rows are community-verified (`verified=yes`) and online at dump time.
- FAQ: "PhishTank is free to everyone, both the website and the data (via the
  API)" and API use is OK for both commercial and non-commercial uses.
- Keyless downloads are "limited to a few downloads per day"; a free
  application key (registration + email confirmation) gives
  `http://data.phishtank.com/data/<key>/online-valid.csv.bz2`. A descriptive
  `User-Agent` header is required.

**Not verified / caveats**

- No Creative-Commons-style licence text was found on the pages fetched (the
  footer "Terms of Use" link did not render a separate data-licence page in our
  check). Treat it as *operator-permitted use with attribution*, not a formal
  licence; re-check before redistributing the data.
- The dump was **not downloaded** during Day 8 — reliable bulk access needs a
  key, and keyless access is rate-limited.

## Source 2 — Tranco top-sites ranking (negative/legitimate class)

- Operator: research service (Le Pochat et al.; DSN paper), tranco-list.eu.

**Verified from <https://tranco-list.eu/> (19 Oct 2026)**

- Research-oriented ranking hardened against manipulation, with permanent
  citable list IDs (reproducible snapshots) — good provenance.
- Daily list published by 0:00 UTC; the `Last-Modified` header gives an exact
  timestamp; past versions are downloadable.
- File format is the Alexa/Cisco Umbrella style `rank,domain` CSV (zipped).
- The homepage states Google Safe Browsing filtering is enabled to remove
  known-malicious websites, which reduces label noise in the legitimate class.
- Provider attribution/licences listed on the page: Cisco Umbrella (free of
  charge), Majestic (**CC BY 3.0**), Chrome UX Report (**CC BY-SA 4.0**),
  Cloudflare Radar (**CC BY-NC 4.0**), plus Farsight for the default list.

**Not verified / caveats**

- The Cloudflare Radar component is **non-commercial** — relevant if PhishGuard
  is ever commercial. Options: cite Tranco and check the terms, or build a
  custom Tranco list without that provider, or use an alternative such as the
  Majestic Million (CC BY 3.0).
- Tranco's own terms page was not reachable during the check (`/about` → 404),
  so Tranco's own licence text is **unverified**; citing the paper is the
  documented practice.
- The list was **not downloaded** during Day 8.
- "Top sites" ≠ "guaranteed benign": a popular domain can be compromised.
  Tranco's GSB filter mitigates but does not eliminate this.

## Alternatives considered and rejected

- **UCI "Phishing Websites" (CC BY 4.0, DOI 10.24432/C55W25)** — reputable and
  clearly licensed, but it ships engineered feature vectors, not raw URL
  strings, so the analyzer cannot be evaluated on it.
- **OpenPhish community feed** — useful, but its terms restrict redistribution
  and it lacks the provenance fields PhishTank provides.
- **URLhaus (abuse.ch)** — malware *distribution* URLs rather than phishing, so
  it does not match the positive class definition.

## Manual acquisition (nothing here runs automatically)

PhishTank:

1. Register free at phishtank.com and confirm the email address.
2. Open the API page to read the application key.
3. Download with a descriptive User-Agent, e.g.
   `curl -A "phisguard-eval/0.1 (research)" -o phishtank-online-valid.csv.bz2 "http://data.phishtank.com/data/<KEY>/online-valid.csv.bz2"`
   (keyless: `http://data.phishtank.com/data/online-valid.csv.bz2`, rate-limited).
4. Decompress into `backend/eval/data/phishtank-online-valid.csv`.

Tranco:

1. Open <https://tranco-list.eu/> and use "Retrieve latest list" (note the list
   ID shown on the following page for reproducibility).
2. Save the zip under `backend/eval/data/` and extract
   `backend/eval/data/tranco-top-1m.csv`.

## Import and evaluate (all offline)

```bat
cd backend
.venv\Scripts\python.exe eval\import_dataset.py phishtank eval\data\phishtank-online-valid.csv --limit 1000 --out eval\data\phishtank.jsonl
.venv\Scripts\python.exe eval\import_dataset.py tranco eval\data\tranco-top-1m.csv --limit 1000 --out eval\data\tranco.jsonl
.venv\Scripts\python.exe eval\import_dataset.py merge eval\data\phishtank.jsonl eval\data\tranco.jsonl --out eval\data\eval-dataset.jsonl
.venv\Scripts\python.exe eval\evaluator.py --fixtures eval\data\eval-dataset.jsonl
```

Each import writes a `<file>.jsonl.meta.json` sidecar with source URL, licence
note, input SHA-256, row counts and import time — keep it with any reported
numbers so results stay reproducible.

## Known limitations to state whenever these numbers are quoted

- PhishTank rows may already be offline by evaluation time; we deliberately do
  not check (no URL is ever fetched), so "suspicious" means *reported and
  community-verified phishing*, not *currently live*.
- Some phishing URLs are simple and will score Low; some legitimate URLs look
  odd and will score High. That is what the evaluation measures — do not
  "fix" the held-out set by editing labels.
- 1,000-vs-1,000 subsets are a convenience, not a population sample; report the
  sample size, list ID / dump date and filters every time.
