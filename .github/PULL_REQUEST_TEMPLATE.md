## Summary

<!-- Briefly describe what this PR adds or fixes. -->

## Related Issue

- Closes #

## Type of Change

- [ ] New security blog RSS/Atom/sitemap/HTML feed in `sources.yaml`
- [ ] New pre-CVE or marketing trap test case in `benchmarks/`
- [ ] New `zerobom.backends` plugin or backend improvement
- [ ] Verification / ingestion / alerting bug fix or enhancement
- [ ] Documentation update

## Engineering & Security Checklist

- [ ] No LLM version comparisons introduced (all range evaluation uses `univers` / `osv_compiler`).
- [ ] No live network or LLM calls added to unit tests (`pytest` runs 100% offline).
- [ ] Untrusted inputs (HTML, XML, SBOMs, URLs, package coordinates) enforce scheme/allowlist, size, and injection guards.
- [ ] No runtime `assert` statements used for validation inside `src/` or `plugins/`.
- [ ] Added or updated unit tests for all behavioral changes.
- [ ] All checks pass locally:
  - `uv run ruff check . && uv run ruff format --check .`
  - `uv run mypy src/ && uv run mypy --strict plugins/zerobom-aws/src plugins/zerobom-gcp/src plugins/zerobom-azure/src`
  - `uv run pytest -v`
  - `uv run python benchmarks/run_evals.py --mode offline`
