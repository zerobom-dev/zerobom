"""Deterministic, ReDoS-safe keyword and regex pre-filter executed before the LLM layer."""

from __future__ import annotations

import re

from zerobom.models import PrefilterResult, RawArticle

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
_GHSA_RE = re.compile(
    r"\bGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-"
    r"[23456789cfghjmpqrvwx]{4}\b",
    re.IGNORECASE,
)
_ZDI_CAN_RE = re.compile(r"\bZDI-CAN-\d{4,7}\b", re.IGNORECASE)
_ZDI_RE = re.compile(r"\bZDI-\d{2}-\d{3,5}\b", re.IGNORECASE)
_TALOS_RE = re.compile(r"\bTALOS-\d{4}-\d{4,5}\b", re.IGNORECASE)
_CERT_VU_RE = re.compile(r"\bVU#\d{5,7}\b", re.IGNORECASE)
_OSV_ADV_RE = re.compile(r"\b(?:RUSTSEC|GO|PYSEC)-\d{4}-\d{4,6}\b", re.IGNORECASE)

_ALIAS_EXTRACTORS: tuple[tuple[re.Pattern[str], bool], ...] = (
    (_CVE_RE, False),
    (_GHSA_RE, True),
    (_ZDI_CAN_RE, False),
    (_ZDI_RE, False),
    (_TALOS_RE, False),
    (_CERT_VU_RE, False),
    (_OSV_ADV_RE, False),
)

# Simple non-backtracking patterns used prior to LLM extraction.
_VULN_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("zero_day", re.compile(r"\b(?:0-day|zero-day|zero day|actively exploited)\b", re.I)),
    ("vulnerability", re.compile(r"\bvulnerabilit(?:y|ies)\b", re.I)),
    ("rce", re.compile(r"\b(?:rce|(?:remote|arbitrary|unauthenticated) code execution)\b", re.I)),
    (
        "dos",
        re.compile(
            r"\b(?:denial[- ]of[- ]service|redos|infinite loop|resource exhaustion)\b",
            re.I,
        ),
    ),
    ("ssrf", re.compile(r"\b(?:ssrf|server-side request forgery)\b", re.I)),
    ("xss", re.compile(r"\b(?:xss|cross-site scripting|open redirect)\b", re.I)),
    ("sqli", re.compile(r"\b(?:sqli|sql injection|nosql injection|ldap injection)\b", re.I)),
    ("request_smuggling", re.compile(r"\b(?:http )?request smuggling\b", re.I)),
    (
        "xxe_ssti",
        re.compile(r"\b(?:xxe|xml external entity|ssti|server-side template injection)\b", re.I),
    ),
    ("prototype_pollution", re.compile(r"\bprototype pollution\b", re.I)),
    (
        "path_traversal",
        re.compile(
            r"\b(?:path traversal|directory traversal|"
            r"arbitrary file (?:read|write|overwrite|upload))\b",
            re.I,
        ),
    ),
    (
        "auth_bypass",
        re.compile(
            r"\b(?:authentication|authorization|access control|allowlist|pin|mfa|sso|rbac) "
            r"bypass\b|\bunauthenticated access\b|"
            r"\b(?:jwt|oauth|oidc|saml) (?:bypass|forgery|confusion|spoofing)\b",
            re.I,
        ),
    ),
    (
        "priv_esc",
        re.compile(r"\b(?:privilege escalation|lpe|container escape|sandbox escape)\b", re.I),
    ),
    (
        "command_injection",
        re.compile(r"\b(?:command injection|os command injection|code injection)\b", re.I),
    ),
    ("deserialization", re.compile(r"\b(?:unsafe |insecure )?deserialization\b", re.I)),
    ("race_condition", re.compile(r"\b(?:race condition|toctou)\b", re.I)),
    (
        "credentials",
        re.compile(
            r"\b(?:hardcoded (?:credential|password|secret|key)|"
            r"credential (?:leak|exposure))\b",
            re.I,
        ),
    ),
    (
        "supply_chain",
        re.compile(
            r"\b(?:supply[- ]chain|malicious package|dependency confusion|typosquatting)\b",
            re.I,
        ),
    ),
    (
        "memory_corruption",
        re.compile(
            r"\b(?:use-after-free|buffer overflow|heap overflow|stack overflow|"
            r"out[- ]of[- ]bounds|null pointer dereference|integer overflow|type confusion)\b",
            re.I,
        ),
    ),
    (
        "info_disclosure",
        re.compile(r"\b(?:information disclosure|sensitive data exposure)\b", re.I),
    ),
    (
        "security_advisory",
        re.compile(
            r"\b(?:security advisory|security bulletin|security alert|"
            r"security release|security notice|security warning|security update|advisory)\b",
            re.I,
        ),
    ),
    ("cwe", re.compile(r"\bCWE-\d{1,5}\b", re.I)),
    ("exploit_poc", re.compile(r"\b(?:poc|proof of concept|exploit(?:ed|ation)?)\b", re.I)),
    (
        "remediation",
        re.compile(r"\b(?:patched in|fixed in|upgrade to|security (?:fix|patch))\b", re.I),
    ),
)

_SOFTWARE_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "version_literal",
        re.compile(r"(?<![a-z0-9])v?\d+\.\d+(?:\.\d+)?(?:-[a-z0-9.]+)?(?![a-z0-9])", re.I),
    ),
    (
        "version_range",
        re.compile(
            r"\b(?:prior to|before|affected versions?)\b|"
            r"\bversions?\s*(?:<=?|(?:prior|before|through|up to)\b)",
            re.I,
        ),
    ),
    (
        "ecosystem",
        re.compile(
            r"\b(?:pypi|pip|npm|node\.js|maven|gradle|golang|go module|debian|ubuntu|"
            r"alpine|rhel|rpm|crates\.io|cargo|rubygems|nuget|packagist|composer|"
            r"helm|oci|terraform|ansible)\b",
            re.I,
        ),
    ),
    (
        "purl_or_repo",
        re.compile(r"(?:\bpkg:[a-z0-9._-]+/|github\.com/[a-z0-9_.-]+/[a-z0-9_.-]+)", re.I),
    ),
    (
        "package_word",
        re.compile(
            r"\b(?:package|library|crate|module|dependency|container image|"
            r"helm chart|terraform provider)\b",
            re.I,
        ),
    ),
    (
        "enterprise_iam",
        re.compile(
            r"\b(?:keycloak|okta|authentik|ory (?:hydra|kratos)|freeipa|active directory|"
            r"entra id|pingfederate|forgerock|cyberark|hashicorp (?:vault|boundary)|"
            r"gravitational teleport)\b",
            re.I,
        ),
    ),
    (
        "cloud_native_k8s",
        re.compile(
            r"\b(?:kubernetes|k8s|kubelet|kube-apiserver|etcd|containerd|runc|docker|podman|"
            r"istio|cilium|calico|coredns|ingress-nginx|cert-manager|external-secrets|"
            r"rancher|openshift|k3s)\b",
            re.I,
        ),
    ),
    (
        "cicd_devops",
        re.compile(
            r"\b(?:gitlab|github actions|jenkins|argocd|argo workflows|fluxcd|teamcity|"
            r"atlassian bamboo|artifactory|jfrog|sonatype nexus|goharbor|sonarqube|"
            r"apache airflow|prefect)\b",
            re.I,
        ),
    ),
    (
        "enterprise_middleware_web",
        re.compile(
            r"\b(?:nginx|envoy|haproxy|traefik|kong gateway|caddy server|apache http|"
            r"tomcat|jetty|wildfly|spring boot|spring framework|spring security|struts|"
            r"log4j|jackson|netty|grpc|graphql|asp\.net|django|fastapi|flask|"
            r"ruby on rails|laravel|php-fpm)\b|(?<!\w)\.net(?:\s+core)?\b",
            re.I,
        ),
    ),
    (
        "data_messaging_observability",
        re.compile(
            r"\b(?:postgresql|postgres|mysql|mariadb|mongodb|redis|valkey|elasticsearch|"
            r"opensearch|apache kafka|kafka|rabbitmq|nats|clickhouse|snowflake|"
            r"apache spark|apache flink|grafana|prometheus|grafana loki|opentelemetry|"
            r"splunk|wazuh)\b",
            re.I,
        ),
    ),
    (
        "enterprise_edge_vpn",
        re.compile(
            r"\b(?:fortinet|fortios|fortigate|palo alto|pan-os|globalprotect|ivanti|"
            r"pulse secure|citrix|netscaler|f5 big-ip|big-ip|cisco asa|ios xe|"
            r"juniper|junos|sophos|check point|vmware|vsphere|esxi|vcenter)\b",
            re.I,
        ),
    ),
    (
        "ai_llm_serving",
        re.compile(
            r"\b(?:litellm|vllm|ollama|llama\.cpp|llama-cpp-python|sglang|bentoml|"
            r"torchserve|localai|triton inference server|text-generation-inference|"
            r"mlflow|kubeflow|kserve|ray (?:serve|cluster|dashboard)|"
            r"pytorch|tensorflow|keras|onnxruntime|huggingface_hub|safetensors|"
            r"jupyter|jupyterlab|jupyterhub)\b",
            re.I,
        ),
    ),
    (
        "ai_llm_agents_rag",
        re.compile(
            r"\b(?:langchain|langgraph|langflow|langserve|langfuse|llamaindex|llama-index|"
            r"flowise|dify|n8n|open[- ]webui|anythingllm|librechat|lobechat|chainlit|"
            r"comfyui|gradio|streamlit|crewai|autogen|pydantic-ai|semantic kernel|"
            r"model context protocol|mcp[- ]server|fastmcp|"
            r"qdrant|weaviate|milvus|chromadb|pgvector)\b",
            re.I,
        ),
    ),
)

_MARKETING_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("webinar", re.compile(r"\b(?:webinar|register now|join our live)\b", re.I)),
    ("funding", re.compile(r"\bseries [a-e] funding\b", re.I)),
    ("hiring", re.compile(r"\b(?:we'?re hiring|join our team|open positions)\b", re.I)),
    ("conference", re.compile(r"\b(?:conference booth|visit our booth|rsa conference)\b", re.I)),
    ("press_release", re.compile(r"\b(?:press release|gartner|forrester|book a demo)\b", re.I)),
    ("quarterly", re.compile(r"\b(?:quarterly earnings|customer spotlight)\b", re.I)),
)


def _canonicalize_alias(raw_match: str, *, is_ghsa: bool) -> str:
    """Return canonical uppercase/GHSA-lowercase casing for an extracted alias token."""
    if is_ghsa:
        return "GHSA-" + raw_match[5:].lower()
    return raw_match.upper()


def is_valid_advisory_alias(alias: str) -> str | None:
    """Validate and canonicalize a candidate advisory identifier against strict patterns.

    Supports ``CVE-*``, ``GHSA-*``, ``ZDI-CAN-*``, ``ZDI-*``, ``TALOS-*``, ``VU#*``,
    ``RUSTSEC-*``, ``GO-*``, and ``PYSEC-*`` identifiers.

    Args:
        alias: Candidate identifier string returned by pre-filtering or an LLM.

    Returns:
        Canonical identifier string if strictly valid, otherwise ``None``.
    """
    cleaned = alias.strip()
    if not cleaned or len(cleaned) > 64:
        return None
    for pattern, is_ghsa in _ALIAS_EXTRACTORS:
        # Compare strict full-string pattern without word-boundary quirks on '#'.
        match = pattern.search(cleaned)
        if match is not None and match.group(0) == cleaned:
            return _canonicalize_alias(cleaned, is_ghsa=is_ghsa)
    return None


def extract_known_aliases(text: str) -> tuple[str, ...]:
    """Extract normalized advisory identifiers (CVE, GHSA, ZDI, TALOS, VU#, OSV) from text.

    Args:
        text: Combined article title and body text.

    Returns:
        Deduplicated tuple of canonical advisory identifiers.
    """
    aliases: list[str] = []
    seen: set[str] = set()

    for pattern, is_ghsa in _ALIAS_EXTRACTORS:
        for match in pattern.findall(text):
            canonical = _canonicalize_alias(match, is_ghsa=is_ghsa)
            if canonical not in seen:
                seen.add(canonical)
                aliases.append(canonical)

    return tuple(aliases)


def prefilter_article(article: RawArticle) -> PrefilterResult:
    """Gate out pure marketing/non-vulnerability posts deterministically before LLM calls.

    Preserves disclosures mentioning newly reserved ``CVE-`` or ``GHSA-`` identifiers (since
    blogs frequently publish days before NVD/OSV assigns ranges) and records them as
    ``extracted_aliases``.

    Args:
        article: Ingested :class:`RawArticle` candidate.

    Returns:
        A :class:`PrefilterResult` containing pass decision, heuristic score, and matched tags.
    """
    combined = f"{article.title}\n{article.body}"
    extracted_aliases = extract_known_aliases(combined)

    vuln_signals = [name for name, pat in _VULN_SIGNAL_PATTERNS if pat.search(combined)]
    if any(alias.startswith("CVE-") for alias in extracted_aliases):
        vuln_signals.append("cve")
    if any(alias.startswith("GHSA-") for alias in extracted_aliases):
        vuln_signals.append("ghsa")
    if any(not alias.startswith(("CVE-", "GHSA-")) for alias in extracted_aliases):
        vuln_signals.append("precve_id")

    software_signals = [name for name, pat in _SOFTWARE_SIGNAL_PATTERNS if pat.search(combined)]
    marketing_signals = [name for name, pat in _MARKETING_SIGNAL_PATTERNS if pat.search(combined)]

    has_pair = len(vuln_signals) >= 1 and len(software_signals) >= 1
    strong_vuln_only = len(vuln_signals) >= 2 and len(marketing_signals) <= len(vuln_signals)
    passed = has_pair or strong_vuln_only

    raw_score = (
        min(0.50, 0.25 * len(vuln_signals))
        + min(0.40, 0.20 * len(software_signals))
        + (0.10 if extracted_aliases else 0.0)
        - min(0.40, 0.10 * len(marketing_signals))
    )
    score = round(max(0.0, min(1.0, raw_score)), 4)

    reasons: list[str] = []
    if not passed:
        if marketing_signals and not vuln_signals:
            reasons.append("Dropped promotional/marketing article lacking vulnerability signals.")
        else:
            reasons.append(
                "Dropped article lacking coupled vulnerability and software/version signals."
            )

    return PrefilterResult(
        passed=passed,
        score=score,
        vuln_signals=tuple(vuln_signals),
        software_signals=tuple(software_signals),
        marketing_signals=tuple(marketing_signals),
        extracted_aliases=extracted_aliases,
        reasons=tuple(reasons),
    )
