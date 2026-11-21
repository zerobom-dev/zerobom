# zerobom Phase 1 Benchmark & Validation Report

This report documents the reproducible two-tier evaluation of `zerobom`, covering both the deterministic offline CI suite and the `46`-case concise synthetic pre-CVE dev evaluation benchmark.

---

## 1. Benchmark Methodology, Provenance & Limitations

`zerobom` is evaluated across two complementary tiers:

1. **Tier 1 — Offline Deterministic Suite (`16` cases):** Runs in CI with zero network or LLM API keys against golden and adversarial extractor payloads (`benchmarks/datasets/offline_adversarial.json`), verifying quote grounding, generic-name blocking, version-range math (`univers`), routing gates, and deterministic containment of injected outputs.
2. **Tier 2 — Synthetic Pre-CVE Dev Suite (`46` cases):** Evaluates deterministic pre-filtering, LLM structured extraction, two-stage verification, OSV compilation, and `univers` version probing across:
   - `36` concise synthetic historical pre-CVE advisory summaries (`332–584` chars, median `401` chars) spanning PyPI, npm, Maven, Go, Debian, Ubuntu, RPM/Red Hat, CloudLinux, Alpine, Cargo, RubyGems, Composer, NuGet, and generic runtimes (`benchmarks/datasets/precve_cases.json`).
   - `10` marketing, hiring, product-launch, and prompt-injection trap summaries (`285–387` chars; `benchmarks/datasets/marketing_traps.json`).

### Known Limitations & Methodology Disclosures

- **Dev-set iteration (`v1.1` → `v1.4`):** Prompts `v1.1` through `v1.4` were refined using this `46`-case synthetic dataset. While every deterministic gate is independent of prompts, Tier 2 accuracy numbers reflect dev-set performance rather than a held-out corpus.
- **Synthetic brevity vs. live HTML:** Tier 2 fixtures pass clean text directly into `process_article()` rather than full multi-KB scraped HTML documents. Real-world articles face additional risks: non-English posts (dropped by English-focused `prefilter.py` keywords), long writeups exceeding the `24` KB window where affected versions appear in the truncated middle, JS-rendered SPAs/PDFs, paraphrased quotes, and inline prose negation.
- **Statistical uncertainty:** With `n=16` offline and `n=46` synthetic dev cases, `0` observed escapes bounds the true escape probability only within 95% Wilson confidence intervals (`<= 19.36%` offline, `<= 7.71%` Tier 2), not mathematical zero.
- **Re-run & archival:** Each `run_evals.py` execution computes `dataset_sha256` (and `executed_at` UTC for live runs). Archived `v0.1.0` Tier 2 run (`gpt-4o-mini` / `v1.4`, `executed_at`: `2026-11-21T16:58:09.973286+00:00`, `dataset_sha256`: `9fed3844b8c37a945e1a33890bcf32dbbba8214b9f55ce9b7364f4c954e9b93d`) lives at [`results/live-eval-summary.json`](results/live-eval-summary.json) and [`results/live-eval-report.md`](results/live-eval-report.md).

### Reproduce Locally

```bash
# Tier 1: Zero-API-key deterministic offline suite (CI gate)
uv run python benchmarks/run_evals.py --mode offline --output-json .cache/offline-eval.json --output-markdown .cache/offline-eval.md

# Tier 2: Live LLM extraction dev suite (requires ZEROBOM_LLM_* env vars)
uv run python benchmarks/run_evals.py --mode live --output-json benchmarks/results/live-eval-summary.json --output-markdown benchmarks/results/live-eval-report.md
```

---

## 2. Headline Benchmark Results

| Metric | Tier 1: Offline Deterministic (`16` cases) | Tier 2: Synthetic Dev Suite `gpt-4o-mini` / `v1.4` (`46` cases) |
| --- | ---: | ---: |
| **Routing Accuracy** | **100.00%** (`16/16`) | **97.83%** (`45/46`; 95% CI `[88.66%, 99.62%]`) |
| **Package Precision** | **100.00%** (`12/12`, `0` FP) | **100.00%** (`37/37`, `0` FP; 95% CI `[90.59%, 100.00%]`) |
| **Package Recall** | **100.00%** (`12/12`, `0` FN) | **97.37%** (`37/38`; 95% CI `[86.51%, 99.53%]`) |
| **Package F1** | **100.00%** | **98.67%** |
| **Version Probe Accuracy** | **100.00%** (`18/18`) | **96.47%** (`82/85`; `82/82` on compiled OSVs) |
| **Quote Grounding Rate** | **84.21%** (`16/19`, expected adversarial drops) | **97.56%** (`40/41`) |
| **Hallucination Escape Rate** | **0.00%** (`0/16`; 95% CI `[0.00%, 19.36%]`) | **0.00%** (`0/46`; 95% CI `[0.00%, 7.71%]`) |
| **Marketing Trap FP Rate** | **0.00%** (`1/1` marketing trap; `5/5` drops) | **0.00%** (`0/10` leaked; 95% CI `[0.00%, 27.75%]`) |

---

## 3. Prompt & Deterministic Verification Progression (`gpt-4o-mini`, `46` Dev Cases)

| Iteration | Prompt | Key Change | Routing Acc. | P / R / F1 | Probes | Grounding | Halluc. Escape | Mkt FP |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Baseline | `v1.1` | Initial prompt + base verification | 100.00% | 79.0% / 79.0% / 79.0% | 87.06% | 97.44% | 17.39% | 0.00% |
| Hardening Pass 1 | `v1.2` | Strict PURL ecosystem mapping, NVR splitting, `supporting_quotes`, generic/distro rules | 91.30% | 97.4% / 97.4% / 97.4% | 96.47% | 85.71% | 2.17% | 10.00% |
| Hardening Pass 2 | `v1.3` | Post-fence anti-injection sandwich reminder; drop over-strict `supporting_quotes` downgrade | 97.83% | 100.0% / 97.37% / 98.67% | 95.29% | 90.24% | 0.00% | 0.00% |
| **v0.1.0 Dev Final** | **`v1.4`** | **Contiguous bullet-quoting rules + deterministic bounded colon-list & boundary-safe grounding** | **97.83%** | **100.0% / 97.37% / 98.67%** | **96.47%** | **97.56%** | **0.00%** | **0.00%** |

---

## 4. Routing Confusion Matrices

### Tier 1 — Offline Deterministic (`16` cases)

| Expected \ Actual | `auto` | `triage` | `drop` |
| --- | ---: | ---: | ---: |
| `auto` | 6 | 0 | 0 |
| `triage` | 0 | 5 | 0 |
| `drop` | 0 | 0 | 5 |

### Tier 2 — Synthetic Dev Suite `gpt-4o-mini`, Prompt `v1.4` (`46` cases)

| Expected \ Actual | `auto` | `triage` | `drop` |
| --- | ---: | ---: | ---: |
| `auto` | 34 | 0 | 1 |
| `triage` | 0 | 1 | 0 |
| `drop` | 0 | 0 | 10 |

### Single Remaining Dev Miss (`v1.4`)

- `precve-os-24-rpm-openssh` (`auto` -> `drop`): `gpt-4o-mini` returned a paraphrased `evidence_quote` that did not match the article substring. Stage 1 grounding failed closed and dropped the claim cleanly (`0/46` hallucination escape, `0` false positives).

---

## 5. Manual Live-Site Smoke Runs Observed During Phase 1 Development (`gpt-4o-mini`, `v1.4`)

*Note: Raw `.cache/` artifacts from these exploratory Phase 1 runs are not committed in git; reproduce or archive under `benchmarks/results/` before tagging.*

| Target / Flow | Prompt | Observed Outcome | Notes |
| --- | --- | --- | --- |
| **CloudLinux `ZDI-CAN-33367`**<br>`https://cloudlinux.com/security/zdi-can-33367` | `v1.4` | `0.5500 [TRIAGE]` (`--tier unknown`) | Grounded `6/6` kernel stream claims (`CloudLinux:7/8/9/10`, `pkg:rpm/cloudlinux/kernel`) via bounded colon-list grounding and retained `ZDI-CAN-33367` + `CVE-2026-43284` aliases. |
| **CrowdStrike `PHP2Shell`**<br>`https://www.crowdstrike.com/en-us/blog/obstacles-to-weaponizing-php2shell-likely-constrain-exploitation/` | `v1.4` | `0.5500 [TRIAGE]` (`--tier unknown`) | Grounded `4/4` `pkg:generic/php` branches (`< 8.2.35`, `< 8.3.36`, `< 8.4.27`, `< 8.5.12`) and matched sample CycloneDX `pkg:generic/php@8.2.30`. |
| **`zerobom watch` State Dedup** | — | `total_analyzed: 0` on 2nd pass | SQLite URL/content state store skipped previously processed feed items deterministically. |

---

## 6. Full Case Breakdown — Offline Deterministic (`16` cases)

| Case ID | Expected -> Actual | PURLs (TP/FP/FN) | Probes | Escape | Notes |
| --- | --- | --- | --- | --- | --- |
| `offline-gold-01-pypi-requests` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `offline-gold-02-npm-scoped-babel` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `offline-gold-03-maven-log4j` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `offline-gold-04-deb-xz-utils` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `offline-adv-01-generic-blocklist` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `offline-adv-02-registry-404` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `offline-adv-03-fabricated-quote` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `offline-adv-04-bait-and-switch-quote` | `triage` -> `triage` | 1/0/0 | 0/0 | no | OK |
| `offline-adv-05-inverted-version-bounds` | `triage` -> `triage` | 1/0/0 | 0/0 | no | Invalid bounds omit hollow OSV (`expect_osv_compiled=false`) |
| `offline-adv-06-unknown-tier-cap` | `triage` -> `triage` | 1/0/0 | 1/1 | no | OK |
| `offline-adv-07-unbounded-zero-day` | `triage` -> `triage` | 1/0/0 | 1/1 | no | OK |
| `offline-adv-08-marketing-zero-claims` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Marketing trap suppressed cleanly |
| `offline-gold-05-generic-ruby-multibranch` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `offline-gold-06-rpm-cloudlinux-kernel-multistream` | `auto` -> `auto` | 2/0/0 | 4/4 | no | OK |
| `offline-adv-09-registry-runtime-name-blocked` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `offline-adv-10-multi-quote-stitch-bait` | `triage` -> `triage` | 1/0/0 | 0/0 | no | OK |

---

## 7. Full Case Breakdown — Synthetic Dev Suite `gpt-4o-mini` / `v1.4` (`46` cases)

| Case ID | Expected -> Actual | PURLs (TP/FP/FN) | Probes | Escape | Notes |
| --- | --- | --- | --- | --- | --- |
| `precve-pypi-01-requests-netrc` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-pypi-02-urllib3-proxy-auth` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `precve-pypi-03-pyyaml-full-load` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-pypi-04-pillow-imagefont` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `precve-pypi-05-cryptography-pkcs12` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-pypi-06-jinja2-attr-escape` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-npm-07-lodash-proto` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-npm-08-babel-traverse` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-npm-09-axios-ssrf` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `precve-npm-10-semver-redos` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-npm-11-express-open-redirect` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-npm-12-ws-dos` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-maven-13-log4j-jndi` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-maven-14-spring-beans` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-maven-15-jackson-databind` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-maven-16-netty-http2` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-maven-17-commons-text` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-go-18-gin-proxy-header` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-go-19-golang-jwt` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-go-20-x-crypto-ssh` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-go-21-gogo-protobuf` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-go-22-gorilla-websocket` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-os-23-deb-xz-utils` | `auto` -> `auto` | 1/0/0 | 3/3 | no | OK |
| `precve-os-24-rpm-openssh` | `auto` -> `drop` | 0/0/1 | 0/3 | no | Missing compiled OSV advisory for 3 expected version probe(s).; All extracted package claims were dropped during verification. |
| `precve-os-25-apk-curl` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-os-26-deb-ubuntu-sudo` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-os-27-deb-openssl` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-cargo-28-rustls` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-gem-29-activesupport` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-composer-30-symfony` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-nuget-31-newtonsoft` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-edge-32-multipkg-fastapi-starlette` | `auto` -> `auto` | 2/0/0 | 4/4 | no | OK |
| `precve-edge-33-unknown-tier-redis` | `triage` -> `triage` | 1/0/0 | 2/2 | no | OK |
| `precve-edge-34-prompt-injection-werkzeug` | `auto` -> `auto` | 1/0/0 | 2/2 | no | OK |
| `precve-generic-35-ruby-multibranch` | `auto` -> `auto` | 1/0/0 | 6/6 | no | OK |
| `precve-os-36-cloudlinux-kernel-zdi` | `auto` -> `auto` | 2/0/0 | 4/4 | no | OK |
| `trap-mkt-01-series-b` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-02-webinar-invite` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-03-hiring-careers` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-04-customer-case-study` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-05-conference-recap` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-06-product-launch-v3` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `trap-mkt-07-feature-release-django` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
| `trap-mkt-08-retrospective-essay` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-09-quarterly-report` | `drop` -> `drop` | 0/0/0 | 0/0 | no | Prefilter dropped non-vulnerability or marketing article. |
| `trap-mkt-10-prompt-injection-spam` | `drop` -> `drop` | 0/0/0 | 0/0 | no | OK |
