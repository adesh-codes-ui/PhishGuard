# Day 6: False-Negative Investigation (Offline, Synthetic)

## Audit (evidence)
Inspected: evaluation report, fixtures, evaluator, analyzer, and classification thresholds (_classify: 0-24 Low, 25-49 Medium, 50-74 High, 75-100 Critical).

All FNs from the synthetic set:
- http://192.168.0.1/ exp=suspicious act=Medium score=40; findings: ip_address_host(25,high)+no_https(15,medium)
- https://paypal.com.evil.net/ exp=suspicious act=Medium score=30; brand_in_subdomain(30,critical)
- https://appleid.evil.com/ exp=suspicious act=Medium score=30; brand_in_subdomain(30,critical)
- http://2130706433/ exp=suspicious act=Medium score=40; numeric_host(25,high)+no_https(15,medium)

All rules fire correctly; no missing rules. The cause is **thresholding/banding**: single strong signals give Medium (e.g. critical-weight 30 → Medium; high+medium sum to 40 → Medium). Threshold for "positive" in the evaluator is High/Critical; under this policy they are FNs.

Other cases: TPs are High (65), TNs all Low, FP 0.

## Cause analysis
- Main cause: classification thresholds (not missing rules, not weight values alone in a vacuum, not fixture labels).
- Changing thresholds to flag Medium as positive would flip these 4 FNs to TPs on this set (recall 1.0, precision 1.0) but risks increasing FP on other data; we explicitly do **not** tune thresholds/weights to fit this synthetic set.

## Recommendations (minimal, evidence-based)
- Keep thresholds as-is unless justified by a separate held-out dataset.
- Consider UI/alerting policy (treat Medium-or-higher as suspicious) without changing numeric scores/thresholds if desired.
- Expand evaluation with a larger held-out dataset before any threshold change.
- No changes to VT separation (already enforced).

## Verification
- Backend: 170 passed, 1 warning (no regressions). No code changes.
- Frontend: production build succeeded.

## Before/After (synthetic set only)
Before (High/Critical positive): TP=2 FN=4 FP=0 TN=6, Acc=0.667, Prec=1.000, Rec=0.333, Spec=1.000, F1=0.500
After (if Medium+ flagged positive, illustrative only): TP=6 FN=0 FP=0 TN=6, Acc=1.000, Prec=1.000, Rec=1.000, Spec=1.000, F1=1.000
*Disclosure: synthetic-only; not generalizable.*

## Changes made
None. No code modified in this step.
