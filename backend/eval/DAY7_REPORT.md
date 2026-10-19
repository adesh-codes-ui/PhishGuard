# Day 7: Risk Threshold Analysis (Exploratory)

**Important:** Production thresholds unchanged. All findings below are exploratory and come only from a **small, synthetic fixture set: 12 URLs (6 suspicious / 6 legitimate)**. They must not be used to choose production thresholds.

## Current state
- Bands: Low 0-24, Medium 25-49, High 50-74, Critical 75-100
- Evaluator (Day 5): positive if High/Critical (>=50) → TP=2 FN=4 FP=0 TN=6, Acc=0.667, Prec=1.000, Rec=0.333, Spec=1.000, F1=0.500

## Exploratory analysis (score>=T positive)
Synthetic fixtures only — 12 total (6 suspicious / 6 legitimate); no weights or thresholds were tuned on them. T=0 gives FP=6 because all suspicious are ≥40 but also all legit score 0; T≥10 keeps FP=0 while max recall on this set is 1.0 at T<=30 (TP=6, FN=0). At T=40, recall drops to 0.667; at T>=50, 0.333.

Full threshold table — **small synthetic dataset (n=12)**, as computed by `eval/analyze_thresholds.py`:
```
 T TP FN FP TN  Acc  Prec   Rec  Spec    F1   FPR
 0  6  0  6  0  0.500 0.500 1.000 0.000 0.667 1.000
10  6  0  0  6  1.000 1.000 1.000 1.000 1.000 0.000
15  6  0  0  6  1.000 1.000 1.000 1.000 1.000 0.000
20  6  0  0  6  1.000 1.000 1.000 1.000 1.000 0.000
25  6  0  0  6  1.000 1.000 1.000 1.000 1.000 0.000
30  6  0  0  6  1.000 1.000 1.000 1.000 1.000 0.000
40  4  2  0  6  0.833 1.000 0.667 1.000 0.800 0.000
50  2  4  0  6  0.667 1.000 0.333 1.000 0.500 0.000
65  2  4  0  6  0.667 1.000 0.333 1.000 0.500 0.000
75  0  6  0  6  0.500 nan   0.000 1.000 nan   0.000
```

Observations (small synthetic set only, n=12): T=25-30 gives perfect metrics on this set (FP=0, Rec=1.0). This matches Day 6: FNs at T>=50 are banding-driven, not rule-driven. However, this is purely post-hoc on a tiny synthetic dataset and is not evidence that any of these thresholds generalizes.

## Recommendations
- **Do not change production thresholds/bands.** Selecting T from this set is not generalizable.
- Use a separate, representative, labelled held-out dataset before any threshold adjustment.
- If operationally needed, consider policy-level alerting (e.g. flag Medium+) without altering numeric bands; document tradeoffs.
- Keep heuristic scoring independent of VirusTotal.

## Verification
Re-run on 18 Oct 2026 (both interpreters, same code):

- Backend, project venv `backend/.venv` — fastapi 0.143.3, starlette 1.8.0, httpx 0.28.1, pytest 8.4.2: **172 passed, 1 warning, 0 failures, 0 errors.**
- Backend, system Python 3.12.10 — fastapi 0.110.0, starlette 0.36.3, httpx 0.27.2, pytest 8.4.2: **172 passed, 20 warnings, 0 failures, 0 errors.** The 20 warnings are all `DeprecationWarning: The 'app' shortcut is now deprecated` raised by httpx inside starlette 0.36.3's TestClient; they are environment-specific and are not test failures.
- Clean environment, `requirements.txt` as declared: brand-new venv, `pip install -r requirements.txt` (exit 0) resolved fastapi 0.146.0, starlette 1.9.0, httpx 0.28.1, pytest 8.4.2 → **172 passed, 1 warning, 0 failures.** This is a from-scratch install, so the dependency file itself is verified, not just the pre-existing `.venv`.
- Frontend: production build succeeded (`tsc -b && vite build`, 35 modules, no errors; `dist/assets/index-*.js` 278.50 kB).
- Threshold-analysis utility: `python eval/analyze_thresholds.py` runs successfully; its table matches the one above.
- No production thresholds modified. API/frontend compatibility preserved.

## Day 7 cleanup (final)
- `backend/requirements.txt`: declared `starlette>=1.8,<2.0` explicitly and documented the verified fastapi/starlette/httpx combination; no framework upgrades, other ranges unchanged.
- pytest resolved to the declared `pytest>=8.2,<9.0` (8.4.2) in both interpreters.
- Application source, scoring weights, production bands, and API behavior untouched.

## Files added
- backend/eval/analyze_thresholds.py
- backend/tests/test_thresholds.py
- backend/eval/DAY7_REPORT.md
- eval/__init__.py updated (no functional change)
