# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| `0.1.x` | Yes |

## Reporting a Vulnerability

Please **do not** report security vulnerabilities through public GitHub issues.

Report vulnerabilities privately through **GitHub Private Vulnerability Reporting** (`https://github.com/zerobom-dev/zerobom/security/advisories/new`).

Please include:
- Affected component and version (`zerobom --version`).
- Minimal reproduction steps or sanitized proof-of-concept input (e.g., crafted blog HTML, feed XML, SBOM fixture, or webhook payload).
- Potential impact (SSRF bypass, injection, verification bypass, credential leak, DoS).

You can expect an initial acknowledgement within **72 hours** and coordinated disclosure once a fix and regression test are verified.

## Security Boundaries & Threat Model

`zerobom` treats all external security blog HTML/text, RSS/Atom/sitemap XML, CycloneDX/SPDX SBOM payloads, package names, version strings, and LLM outputs as **untrusted adversarial input**:

- **No LLM version math or ungrounded auto-alerts:** Version matching uses `univers` deterministically; missing, paraphrased, unbounded, or ungrounded claims drop credibility below the `0.75` `AUTO` threshold.
- **SSRF & DNS rebinding posture:** `SafeHttpFetcher`, registry checks, OCI blob redirects, and webhook/Slack senders reject private/loopback/link-local/IMDS (`169.254.169.254`) and multicast IPs, restrict URI schemes (`http`/`https`), disable implicit proxy inheritance (`trust_env=False`), and disable redirects by default or validate every hop (`<= 3`). Until pinned-IP socket transport lands in `v0.2.0`, deploy `zerobom watch` and `triage-worker` behind an egress firewall or proxy that blocks private and cloud metadata IP ranges at the network layer to defend against `TTL=0` DNS-rebinding TOCTOU.
- **XML, JSON & Terminal Injection Posture:** Feed parsing rejects DOCTYPE/ENTITY declarations across encodings via `expat` pre-scanning; untrusted JSON parsers enforce byte/depth ceilings and handle `RecursionError`; Rich terminal rendering strips ANSI/OSC-8 escapes and C0/C1 control characters.
- **Query & command injection posture:** SQLite queries are parameterized; YAML uses `yaml.safe_load`; untyped queries validate strict ASCII package coordinate allowlists before constructing Solr/CEL/KQL filters; zero `eval`, `exec`, `pickle`, or `shell=True`.
- **Third-Party LLM Data Egress:** When running `zerobom check` or `zerobom watch` against a hosted OpenAI-compatible API (`ZEROBOM_LLM_BASE_URL`), fetched article titles, URLs, and windowed article text (up to `24` KB) are sent to that provider. Software inventories (SBOMs, container/K8s/cloud assets) are **never** sent to the LLM. Use local Ollama (`http://localhost:11434/v1`) or offline `zerobom scan` for zero external egress.
- **Plugin Code-Execution Trust Boundary:** Inventory backends discovered via Python `zerobom.backends` entry points (`importlib.metadata`) are imported and executed in-process with full `zerobom` privileges (no sandboxing). Only install trusted backend plugin packages.
- **Signed callbacks & redaction:** `triage-worker` verifies Slack `X-Slack-Signature` HMACs with a `300` second replay window, binds to loopback `127.0.0.1` by default, enforces payload and socket timeout ceilings, and scrubs API keys, webhook paths, and query parameters from logs and exceptions. Terminate TLS at a reverse proxy and restrict Slack workspace/channel installation until `allowed_team_ids`/`allowed_user_ids` allowlists land in `v0.2.0`.
