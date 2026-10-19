# Evaluation fixtures

This is a **small, synthetic, offline-only fixture set** for Day 5 evaluation.

- URLs are constructed for testing rules (brand-in-subdomain, numeric hosts, IP hosts, userinfo, HTTPS, default-port normalization, scheme detection, brand-FP guards, etc.). 
- They are **not** claimed to be externally verified live phishing URLs.
- No fixture URL is fetched, submitted, or resolved. Evaluation runs entirely against the static analyzer.
- Results from this small set are indicative only; a separate held-out dataset is needed for proper evaluation. No heuristic weights were tuned on this set.

## Day 8: external datasets

See [`DATASETS.md`](DATASETS.md) for the labelled sources (PhishTank, Tranco),
their verified licence/provenance status, manual acquisition steps, and the
`import_dataset.py` interface. Downloaded data belongs in `eval/data/`
(gitignored) and must never be committed. The default dataset here stays the
synthetic `fixtures.jsonl`; external data is opt-in via
`python eval/evaluator.py --fixtures <path>`.