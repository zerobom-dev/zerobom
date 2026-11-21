"""GitHub Code Scanning-compliant SARIF 2.1.0 serializer for ``zerobom`` findings."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from zerobom._version import REPOSITORY_URL, __version__
from zerobom.models import OsvAdvisory, PipelineOutcome

SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_VERSION = "2.1.0"

_SEVERITY_TO_SARIF: dict[str, tuple[str, str]] = {
    "CRITICAL": ("error", "9.5"),
    "HIGH": ("error", "7.5"),
    "MEDIUM": ("warning", "5.5"),
    "LOW": ("note", "3.0"),
    "UNKNOWN": ("warning", "5.0"),
}


def _driver_version() -> str:
    """Return installed ``zerobom`` distribution version, falling back cleanly offline."""
    return __version__


def _to_repo_relative_uri(raw_path: str | None, repo_root: Path | None) -> str:
    """Convert a local path or remote inventory URI into a clean relative POSIX URI."""
    if not raw_path or not raw_path.strip():
        return "sbom.json"

    cleaned = raw_path.strip()
    if "://" in cleaned:
        parsed = urlparse(cleaned)
        parts: list[str] = []
        if parsed.netloc:
            parts.append(parsed.netloc)
        parts.extend(seg for seg in parsed.path.split("/") if seg)
        # Preserve bucket/project/path structure so distinct remote locations do not collide.
        safe_segments = [
            seg.replace("\\", "/").replace(":", "_") for seg in parts if seg not in {".", ".."}
        ]
        joined = "/".join(seg for seg in safe_segments if seg)
        return joined or "inventory-asset"

    path_obj = Path(cleaned)
    roots = [repo_root] if repo_root is not None else [Path.cwd()]
    for root in roots:
        if root is None:
            continue
        try:
            rel = path_obj.resolve().relative_to(root.resolve())
            return rel.as_posix().replace(":", "_")
        except (OSError, ValueError):
            continue

    if path_obj.is_absolute():
        return (path_obj.name or "sbom.json").replace(":", "_")

    normalized_parts = [
        seg.replace(":", "_")
        for seg in cleaned.replace("\\", "/").split("/")
        if seg and seg not in {".", ".."}
    ]
    return "/".join(normalized_parts) or "sbom.json"


def _stable_fingerprint(
    advisory_id: str,
    artifact_uri: str,
    matched_purl: str,
    installed_version: str,
    *,
    backend: str | None = None,
    asset_id: str | None = None,
) -> str:
    """Compute a deterministic alert fingerprint without collapsing distinct cloud/API assets."""
    if backend is not None and backend != "local_sbom" and asset_id is not None:
        payload = (
            f"{advisory_id}|{backend}|{asset_id}|{artifact_uri}|{matched_purl}|{installed_version}"
        ).encode()
    else:
        payload = f"{advisory_id}|{artifact_uri}|{matched_purl}|{installed_version}".encode()
    return hashlib.sha256(payload).hexdigest()[:32]


def _extract_severity(outcome: PipelineOutcome) -> str:
    """Extract normalized severity string from advisory or OSV database_specific metadata."""
    if outcome.advisory is not None:
        return outcome.advisory.severity.value
    if outcome.osv is not None:
        zb_meta = outcome.osv.database_specific.get("zerobom")
        if isinstance(zb_meta, dict):
            raw_sev = zb_meta.get("severity")
            if isinstance(raw_sev, str) and raw_sev.upper() in _SEVERITY_TO_SARIF:
                return raw_sev.upper()
    return "UNKNOWN"


def _extract_help_uri(osv: OsvAdvisory | None) -> str | None:
    """Return first safe HTTP/HTTPS reference URL from an OSV advisory for rule helpUri."""
    if osv is None:
        return None
    for ref in osv.references:
        scheme = urlparse(ref.url).scheme.lower()
        if scheme in {"http", "https"}:
            return ref.url
    return None


def build_sarif_log(
    outcomes: Sequence[PipelineOutcome],
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    """Build a GitHub Code Scanning-compatible SARIF 2.1.0 log dictionary.

    Emits ``tool.driver.rules[]`` definitions with numeric ``security-severity`` tags,
    repo-relative ``artifactLocation.uri`` values, cloud-agnostic asset properties, and
    deterministic ``partialFingerprints``.

    Args:
        outcomes: Sequence of evaluated :class:`PipelineOutcome` entries.
        repo_root: Optional repository root directory used to relativize SBOM paths.

    Returns:
        SARIF 2.1.0 dictionary ready for JSON serialization and upload.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for outcome in outcomes:
        vulnerable = outcome.vulnerable_matches
        if not vulnerable:
            continue

        severity_key = _extract_severity(outcome)
        sarif_level, security_severity = _SEVERITY_TO_SARIF.get(
            severity_key,
            _SEVERITY_TO_SARIF["UNKNOWN"],
        )

        osv = outcome.osv
        help_uri = _extract_help_uri(osv)

        for match in vulnerable:
            rule_id = match.advisory_id
            if rule_id not in rules_by_id:
                summary = osv.summary if osv is not None else f"Pre-CVE advisory {rule_id}"
                details = (osv.details or summary) if osv is not None else summary
                rule_obj: dict[str, Any] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {"text": summary},
                    "fullDescription": {"text": details},
                    "defaultConfiguration": {"level": sarif_level},
                    "properties": {
                        "security-severity": security_severity,
                        "tags": ["security", "sbom", "pre-cve", "zerobom"],
                    },
                }
                if help_uri is not None:
                    rule_obj["helpUri"] = help_uri
                rules_by_id[rule_id] = rule_obj

            raw_location = match.sbom_source or (
                match.asset.location if match.asset is not None else None
            )
            artifact_uri = _to_repo_relative_uri(raw_location, repo_root)
            fixed_hint = (
                f" (fixed in {', '.join(match.fixed_versions)})" if match.fixed_versions else ""
            )
            quote_hint = f' Evidence: "{match.evidence_quote}"' if match.evidence_quote else ""
            message = (
                f"Vulnerable component {match.component_purl} ({match.installed_version}) "
                f"matched {rule_id} [{match.matched_purl}]{fixed_hint}.{quote_hint}"
            )

            result_obj: dict[str, Any] = {
                "ruleId": rule_id,
                "level": sarif_level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": artifact_uri,
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": _stable_fingerprint(
                        rule_id,
                        artifact_uri,
                        match.matched_purl,
                        match.installed_version,
                        backend=match.asset.backend if match.asset is not None else None,
                        asset_id=match.asset.asset_id if match.asset is not None else None,
                    )
                },
            }
            if match.asset is not None:
                # Never leak local host filesystem paths into SARIF properties for local_sbom.
                safe_asset_id = (
                    artifact_uri if match.asset.backend == "local_sbom" else match.asset.asset_id
                )
                asset_props: dict[str, str] = {
                    "backend": match.asset.backend,
                    "assetId": safe_asset_id,
                    "assetType": match.asset.asset_type,
                }
                if match.asset.scope is not None:
                    asset_props["scope"] = match.asset.scope
                result_obj["properties"] = asset_props
            results.append(result_obj)

    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "zerobom",
                        "version": _driver_version(),
                        "informationUri": REPOSITORY_URL,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(
    outcomes: Sequence[PipelineOutcome],
    *,
    repo_root: Path | None = None,
    indent: int = 2,
) -> str:
    """Serialize pipeline outcomes as formatted SARIF 2.1.0 JSON.

    Args:
        outcomes: Sequence of evaluated :class:`PipelineOutcome` entries.
        repo_root: Optional repository root for relativizing SBOM paths.
        indent: JSON indentation spaces.

    Returns:
        Formatted UTF-8 SARIF 2.1.0 JSON string.
    """
    return json.dumps(build_sarif_log(outcomes, repo_root=repo_root), indent=indent)
