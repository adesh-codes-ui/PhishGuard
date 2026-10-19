# Day 5 Evaluation Report (Offline, Synthetic)

## Dataset
- **Source:** `eval/fixtures.jsonl` (synthetic, constructed to exercise rules). 
- **Disclaimer:** Not externally verified live phishing URLs. Distinguish synthetic from real labelled data.
- **Size:** 12 examples (6 suspicious, 6 legit).
- **No network:** All evaluations run against `app.analyzer` only (no URL fetching, no external calls).

## Results
```
Fixtures: 12 | TP=2 FN=4 FP=0 TN=6 | errors=0
Accuracy:  0.667
Precision: 1.000
Recall:    0.333
Specificity: 1.000
F1:        0.500
```

Confusion (threshold: High/Critical = positive = suspicious):
- PRED_HIGH: TP=2, FP=0
- PRED_LOW/MED: FN=4, TN=6

## Per-example breakdown
TP (detected as High/Critical):
- https://paypal.com.secure-login.example.net/ → High (brand_in_subdomain + credential_keywords + multiple_subdomains)
- http://user:pass@evil.com/phish → High (at_symbol + no_https + userinfo_present)

FN (misclassified as Low/Medium despite suspicious label):
- http://192.168.0.1/ → Medium (ip_address_host + no_https), score 40. Threshold for High is >=50; this is Medium.
- https://paypal.com.evil.net/ → Medium (brand_in_subdomain), score 30; brand_in_subdomain is critical weight (30) alone → Medium.
- https://appleid.evil.com/ → Medium (brand_in_subdomain), score 30.
- http://2130706433/ → Medium (no_https + numeric_host), score 40.

TN (legit, not flagged High): all 6 legit examples (including `groups.com`, `purchase.example.com`, and bare host with embedded URL) correctly Low.

FP: 0.

## Grouping by rule (causes)

**False Negatives (missed High/Critical detection)**
- IP host alone: `http://192.168.0.1/` triggers `ip_address_host` (high, 25) + `no_https` (medium, 15) = 40 (Medium). Rationale: IP-based links are flagged, but not enough to reach High; current scoring treats IP as strong signal but combined with HTTP-only gives Medium.
- Brand-in-subdomain alone: `paypal.com.evil.net`, `appleid.evil.com` trigger `brand_in_subdomain` (critical, 30) → score 30 (Medium). Rationale: single critical signal gives Medium under current bands (Medium starts at 25; High starts at 50). Also note brand matching refinement (token-based) prevents FPs; detection is as designed.
- Obfuscated numeric host: `http://2130706433/` → `numeric_host` (high,25)+`no_https`(15)=40 (Medium). Same banding issue.
- These are **banding/weighting effects** (single strong signal often yields Medium) rather than missing rules. No rule is failing to fire.

**False Positives**
- None on this fixture set (0 FP). Brand-FP guards (short-brand token boundary, startswith for longer brands) correctly avoid flagging `groups.com`, `purchase.example.com`, `backup.example.com` etc.

## Recommendations
- **Do not tune weights on this tiny synthetic set.** Results are illustrative only; use a separate, larger held-out dataset for any tuning.
- **Consider banding/alerting policy** (e.g., flag Medium-or-higher as "suspicious" in UI/alerting) if operationally desired; current threshold uses High/Critical for "positive". This explains recall 0.333 on this set.
- **Expand evaluation** with more diverse synthetic+curated cases (path/query tricks, punycode variants, more brand cases) and track per-rule coverage.
- **Keep heuristics independent** of VirusTotal verdicts (already enforced).

## Verification
- Backend tests: **170 passed, 1 warning** (unchanged). Tests include new `tests/test_eval.py` (3 tests).
- Frontend build: **succeeded**.

## Files added
- `backend/eval/fixtures.jsonl` (synthetic fixtures)
- `backend/eval/evaluator.py` (offline evaluator, metrics, breakdown)
- `backend/eval/__init__.py`
- `backend/eval/README.md`
- `backend/eval/EVALUATION_REPORT.md` (this report)
- `backend/tests/test_eval.py` (unit tests for evaluator)
