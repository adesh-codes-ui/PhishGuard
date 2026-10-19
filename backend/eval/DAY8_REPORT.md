# Day 8: Better Dataset and Detection Validation — Progress Report

**Safety statement:** no dataset file was downloaded on Day 8, no dataset URL was
visited/resolved/submitted, and no application source, scoring weight, production
band or API behavior was changed. Bands remain Low 0-24, Medium 25-49,
High 50-74, Critical 75-100 (`app/analyzer.py:339-345`).

## 1. Inspection of the existing evaluation stack

- `eval/evaluator.py` — loads `fixtures.jsonl` (`url` + `label`), predicts
  High/Critical = positive, prints confusion + accuracy/precision/recall/
  specificity/F1. No network I/O.
- `eval/fixtures.jsonl` — 12 synthetic rows (6 suspicious / 6 legitimate),
  header comment states they are not externally verified live phishing URLs.
- `tests/test_eval.py` — 3 tests (fixtures non-empty, predictor behaves,
  evaluate runs).
- `eval/README.md` — documents the synthetic, offline-only nature of the set.
- `eval/DAY7_REPORT.md` — Day 7 verification (172 passed / 20 warnings on the
  system interpreter, 1 warning in `.venv`, clean-env install verified).

## 2. Dataset sources — what is actually verified

Both candidates were read at their **official pages on 19 Oct 2026**. Full
detail, caveats and acquisition steps: `eval/DATASETS.md`.

### Positive class: PhishTank verified phishing CSV (Cisco Talos)
Verified from `phishtank.com/faq.php` and `phishtank.com/developer_info.php`:
- Dump endpoint `http://data.phishtank.com/data/online-valid.csv[.gz|.bz2]`, hourly updates.
- Documented CSV header: `phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target`
  — ISO-8601 per-row provenance (submission + verification timestamps).
- Rows are community-verified and online at dump time.
- FAQ: data is free via website and API; API use OK for commercial **and**
  non-commercial uses.
- Keyless downloads limited to a few per day; a free application key (registration)
  is the documented route, with a descriptive `User-Agent`.

**Not verified:** no formal CC-style licence text was found on the pages fetched
(the footer "Terms of Use" link did not render a separate data-licence page).
Treated as operator-permitted use with attribution, to be re-checked before
redistribution. **The dump was not downloaded.**

### Negative class: Tranco top-sites list
Verified from `tranco-list.eu`:
- Research ranking with permanent citable list IDs (reproducible snapshots),
  daily publication by 0:00 UTC with `Last-Modified` timestamps, archived past
  versions — strong provenance.
- Alexa/Cisco-Umbrella style `rank,domain` CSV (zipped).
- Google Safe Browsing filtering enabled to remove known-malicious sites
  (reduces label noise in the "legit" class).
- Provider licences stated on the page: Umbrella (free of charge),
  Majestic **CC BY 3.0**, CrUX **CC BY-SA 4.0**, Cloudflare Radar **CC BY-NC 4.0**,
  Farsight (default list).

**Not verified:** Tranco's own terms page (`/about` → 404 during our check) and
the download itself. **The list was not downloaded.** Caveat recorded: the
CC BY-NC 4.0 Cloudflare Radar component matters for commercial use.

### Alternatives considered and why rejected
- UCI *Phishing Websites* (CC BY 4.0, DOI 10.24432/C55W25): clearly licensed but
  ships engineered feature vectors, not raw URL strings → unusable for the analyzer.
- OpenPhish: redistribution-restrictive terms, weaker provenance fields.
- URLhaus (abuse.ch): malware-distribution URLs, not the phishing class.

## 3. What was built (import interface, not acquisition)

| File | Change |
|---|---|
| `backend/eval/import_dataset.py` | **new** — `phishtank` / `tranco` / `merge` subcommands: validates the documented CSV header, filters (`--limit`, `--since`), de-duplicates, writes evaluator-compatible JSONL plus a `.jsonl.meta.json` provenance sidecar (source URL, licence note, input SHA-256, row counts, import time, no-network note). Contains no network code. |
| `backend/tests/test_dataset_import.py` | **new** — 23 tests over tiny synthetic CSVs in temp dirs: labelling, dedupe, empty-URL skip, `--since`/`--limit`, missing-column errors, domain validation, sidecar contents, merge-first-wins, full round-trip through `evaluator.load_fixtures`/`evaluate`, plus a guard test that the importer source imports no HTTP/DNS/subprocess module and never calls `analyze_url`. |
| `backend/eval/DATASETS.md` | **new** — source status table, verified vs unverified claims, licence notes, manual acquisition steps (PhishTank key registration, Tranco list ID), import/evaluate commands, limitations to state whenever numbers are quoted. |
| `backend/eval/evaluator.py` | added optional `--fixtures PATH` (default unchanged: synthetic `fixtures.jsonl`); external datasets get a different LIMITATIONS footer. |
| `backend/eval/README.md` | pointer to `DATASETS.md` and the opt-in `--fixtures` usage. |
| `.gitignore` | ignores `backend/eval/data/` and `eval/data/` — downloaded and imported datasets can never be committed. |

Default behavior is unchanged: `python eval/evaluator.py` still evaluates the 12
synthetic fixtures with identical output (TP=2 FN=4 FP=0 TN=6).

## 4. Verification (19 Oct 2026, canonical `backend/.venv`)

- Backend tests: **195 passed, 1 warning, 0 failures** (172 baseline + 23 new).
- CLI smoke test (against throwaway CSVs in `%LOCALAPPDATA%\Temp`, exit 0 each):
  `import_dataset.py phishtank|tranco|merge` all wrote JSONL + meta sidecars;
  `evaluator.py --fixtures <merged>` ran offline and printed the external-data
  LIMITATIONS footer; `evaluator.py` default output unchanged.
- Frontend production build: succeeded (`tsc -b && vite build`, 35 modules,
  `index-*.js` 278.50 kB).
- `app/` untouched: no file under `backend/app/` modified on 19 Oct; bands
  still 75/50/25.

## 5. Explicitly NOT done

- No PhishTank or Tranco data file was downloaded, so **no real-data metrics are
  claimed anywhere in this report**. Availability was verified from official
  documentation only; the files, their exact licences and their byte-level
  formats remain to be checked at acquisition time.
- No production threshold, weight, band, API or UI change.
- No URL from any dataset was fetched, resolved or submitted.

## 6. Next steps

1. Acquire the two files per `DATASETS.md` (PhishTank needs a free API key;
   Tranco needs only the list download) into the gitignored `eval/data/`.
2. Import with `--limit`/`--since`, keep the `.meta.json` sidecars, run
   `evaluator.py --fixtures` and report sample size + list ID + dump date with
   every number.
3. Treat that set as held-out: no weight/threshold tuning on it (Day 7 rule).
