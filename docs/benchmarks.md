# Benchmarks & Evaluation

`zerobom` includes a reproducible two-tier evaluation harness in `benchmarks/run_evals.py` covering deterministic adversarial verification checks (run in CI without network or API keys) and a concise synthetic pre-CVE + marketing-trap dev suite.

## Summary Metrics

| Metric | Tier 1: Offline Deterministic (`16` cases) | Tier 2: Synthetic Dev Suite `gpt-4o-mini` / `v1.4` (`46` cases) |
| --- | ---: | ---: |
| **Routing Accuracy** | **100.00%** (`16/16`) | **97.83%** (`45/46`; 95% CI `[88.66%, 99.62%]`) |
| **Package Precision** | **100.00%** (`12/12`, `0` FP) | **100.00%** (`37/37`, `0` FP; 95% CI `[90.59%, 100.00%]`) |
| **Package Recall** | **100.00%** (`12/12`, `0` FN) | **97.37%** (`37/38`; 95% CI `[86.51%, 99.53%]`) |
| **Package F1** | **100.00%** | **98.67%** |
| **Version Probe Accuracy** | **100.00%** (`18/18`) | **96.47%** (`82/85`; `82/82` on compiled OSVs) |
| **Quote Grounding Rate** | **84.21%** (`16/19`, adversarial drops) | **97.56%** (`40/41`) |
| **Hallucination Escape Rate** | **0.00%** (`0/16`; 95% CI `[0.00%, 19.36%]`) | **0.00%** (`0/46`; 95% CI `[0.00%, 7.71%]`) |
| **Marketing Trap FP Rate** | **0.00%** (`1/1` marketing trap; `5/5` drops) | **0.00%** (`0/10` leaked; 95% CI `[0.00%, 27.75%]`) |

## Dataset Composition & Known Limitations

- **Offline Deterministic (`benchmarks/datasets/offline_adversarial.json`, `16` cases):** Tests golden multi-ecosystem extraction (`PyPI`, scoped `@babel/traverse` `npm`, `Maven`, `Debian` `?upstream=`, generic `Ruby` multi-branch, `CloudLinux` RPM NVR multi-stream) alongside adversarial inputs (generic blocklisted names, 404 registry names, fabricated quotes, bait-and-switch quotes, inverted ranges, unknown tier caps, unbounded zero-days, and split-quote stitching).
- **Synthetic Dev Suite (`46` cases):** Combines `36` concise historical pre-CVE summaries (`benchmarks/datasets/precve_cases.json`, `332–584` chars each) across 14 ecosystems/runtimes and `10` marketing/hiring/prompt-injection traps (`benchmarks/datasets/marketing_traps.json`). Prompt iterations `v1.1`–`v1.4` were refined on this dev set; a held-out full-HTML benchmark split is tracked for `v0.2.0`.
- **Blind spots not covered by synthetic short summaries:** Non-English blog posts (skipped by English prefilter keywords), articles exceeding `24` KB whose affected versions lie in the truncated middle, JavaScript-only SPAs/PDFs, paraphrased quotes, and inline semantic negation.

## Reproducing & Archiving Locally

```bash
# Offline deterministic gate (zero network, zero API keys — byte-identical in CI)
uv run python benchmarks/run_evals.py --mode offline

# Live extraction evaluation against your configured OpenAI-compatible LLM endpoint
export ZEROBOM_LLM_BASE_URL="https://api.openai.com/v1"
export ZEROBOM_LLM_MODEL="gpt-4o-mini"
export ZEROBOM_LLM_API_KEY="sk-..."
uv run python benchmarks/run_evals.py --mode live \
  --output-json benchmarks/results/live-eval-summary.json \
  --output-markdown benchmarks/results/live-eval-report.md
```

For the full case-by-case breakdown and prompt progression history (`v1.1` through `v1.4`), refer to `benchmarks/REPORT.md` in the repository root. The archived `v0.1.0` Tier 2 run (`gpt-4o-mini` / `v1.4`, UTC `2026-11-21T16:58:09.973286+00:00`, `dataset_sha256` `9fed3844b8c37a945e1a33890bcf32dbbba8214b9f55ce9b7364f4c954e9b93d`) is stored alongside it at `benchmarks/results/live-eval-summary.json` and `benchmarks/results/live-eval-report.md`.
