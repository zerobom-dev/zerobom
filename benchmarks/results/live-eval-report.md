# zerobom Benchmark Report (LIVE)

- **Model:** `gpt-4o-mini`
- **Prompt Version:** `v1.4`
- **Total Cases:** `46`
- **Dataset SHA-256:** `9fed3844b8c37a945e1a33890bcf32dbbba8214b9f55ce9b7364f4c954e9b93d`
- **Executed At (UTC):** `2026-11-21T16:58:09.973286+00:00`

## Headline Metrics

| Metric | Value |
| --- | ---: |
| Routing Accuracy | 97.83% |
| Package Precision | 100.00% |
| Package Recall | 97.37% |
| Package F1 | 98.67% |
| Version Probe Accuracy | 96.47% |
| Quote Grounding Rate | 97.56% |
| Hallucination Escape Rate | 0.00% |
| Marketing Trap False-Positive Rate | 0.00% |

## Routing Confusion Matrix

| Expected \ Actual | auto | triage | drop |
| --- | ---: | ---: | ---: |
| `auto` | 34 | 0 | 1 |
| `triage` | 0 | 1 | 0 |
| `drop` | 0 | 0 | 10 |

## Case Breakdown

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
