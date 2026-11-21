"""Cloud-agnostic hardened CycloneDX (1.4-1.6) and SPDX (2.2-2.3) SBOM parser and index.

This module decouples SBOM byte decoding, structure validation, and O(1) component indexing
from local filesystem storage so ``local_sbom``, object-storage plugins (S3/GCS/Azure Blob),
OCI container-registry plugins, and Kubernetes plugins reuse one identical security boundary.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from packageurl import PackageURL
from pydantic import ValidationError

from zerobom.models import (
    MAX_ASSET_METADATA_ENTRIES,
    MAX_ASSET_METADATA_KEY_LENGTH,
    MAX_ASSET_METADATA_VALUE_LENGTH,
    AssetRef,
    InventoryComponent,
    PackageQuery,
)
from zerobom.verify.osv_compiler import _build_upstream_canonical, extract_purl_os_qualifiers
from zerobom.verify.purl import (
    GENERIC_PACKAGE_BLOCKLIST,
    _normalize_pep503,
    _split_namespace_and_name,
    normalize_ecosystem,
)

MAX_SBOM_FILE_BYTES = 50 * 1024 * 1024
MAX_CYCLONEDX_DEPTH = 32

_SPDX_MISSING_SENTINELS: frozenset[str] = frozenset({"NOASSERTION", "NONE"})
_SPDX_PURL_CATEGORIES: frozenset[str] = frozenset({"PACKAGE-MANAGER", "PACKAGE_MANAGER"})


class SbomParseError(ValueError):
    """Raised when an SBOM input path or JSON document violates schema or safety bounds."""


def clean_optional_str(value: Any) -> str | None:
    """Return a stripped non-empty string if ``value`` is a ``str`` without control chars.

    Args:
        value: Untrusted raw JSON or metadata field value.

    Returns:
        Normalized non-empty string, or ``None`` if not a string, empty, or containing ASCII
        control characters (``ord < 32`` or ``127``).
    """
    if not isinstance(value, str):
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        return None
    stripped = value.strip()
    return stripped or None


def build_safe_metadata(pairs: Mapping[str, Any]) -> dict[str, str]:
    """Filter raw metadata fields into bounded, control-char-free key-value pairs.

    Args:
        pairs: Untrusted metadata mapping.

    Returns:
        Bounded dictionary honoring :data:`MAX_ASSET_METADATA_ENTRIES`,
        :data:`MAX_ASSET_METADATA_KEY_LENGTH`, and :data:`MAX_ASSET_METADATA_VALUE_LENGTH`.
    """
    meta: dict[str, str] = {}
    for raw_key, raw_val in pairs.items():
        if len(meta) >= MAX_ASSET_METADATA_ENTRIES:
            break
        clean_key = clean_optional_str(raw_key)
        clean_val = clean_optional_str(raw_val)
        if clean_key is not None and clean_val is not None:
            meta[clean_key[:MAX_ASSET_METADATA_KEY_LENGTH]] = clean_val[
                :MAX_ASSET_METADATA_VALUE_LENGTH
            ]
    return meta


def is_cyclonedx_document(data: Mapping[str, Any]) -> bool:
    """Return ``True`` if ``data`` declares CycloneDX JSON format."""
    return data.get("bomFormat") == "CycloneDX"


def is_spdx_document(data: Mapping[str, Any]) -> bool:
    """Return ``True`` if ``data`` declares an SPDX 2.x JSON format."""
    version = data.get("spdxVersion")
    return isinstance(version, str) and version.startswith("SPDX-2.")


def _extract_spdx_purl(pkg: Mapping[str, Any]) -> str | None:
    """Extract the first valid PURL reference locator from an SPDX package entry."""
    ext_refs = pkg.get("externalRefs")
    if not isinstance(ext_refs, list):
        return None
    for ref in ext_refs:
        if not isinstance(ref, Mapping):
            continue
        category = str(ref.get("referenceCategory", "")).strip().upper()
        ref_type = str(ref.get("referenceType", "")).strip().lower()
        if category in _SPDX_PURL_CATEGORIES and ref_type == "purl":
            locator = clean_optional_str(ref.get("referenceLocator"))
            if locator is not None:
                return locator
    return None


def make_inventory_component(
    *,
    raw_name: Any,
    raw_version: Any,
    raw_purl: Any,
    ecosystem_hint: Any,
    namespace_hint: Any,
    asset: AssetRef,
    bom_ref: Any = None,
) -> InventoryComponent | None:
    """Normalize a raw CycloneDX/SPDX or API component entry into :class:`InventoryComponent`.

    Args:
        raw_name: Raw package name field.
        raw_version: Raw installed version field.
        raw_purl: Raw Package URL string, if present.
        ecosystem_hint: Optional ecosystem identifier when PURL is absent.
        namespace_hint: Optional package group/namespace hint.
        asset: Cloud-agnostic :class:`AssetRef` owning this component.
        bom_ref: Optional CycloneDX ``bom-ref`` or SPDX ``SPDXID``.

    Returns:
        Validated :class:`InventoryComponent`, or ``None`` if required identity fields
        (``name`` and ``version``) are missing or fail strict boundary validation.
    """
    name = clean_optional_str(raw_name)
    version = clean_optional_str(raw_version)
    purl_str = clean_optional_str(raw_purl)
    namespace = clean_optional_str(namespace_hint)
    ecosystem = clean_optional_str(ecosystem_hint)

    canonical_purl: str | None = None
    distro_qualifier: str | None = None
    upstream_package: str | None = None
    upstream_version: str | None = None
    resolved_eco: str | None = ecosystem
    resolved_ns: str | None = namespace

    if purl_str is not None:
        try:
            parsed = PackageURL.from_string(purl_str)
        except ValueError:
            purl_str = None
        else:
            purl_type, hinted_osv = normalize_ecosystem(parsed.type)
            canonical_type = purl_type or parsed.type
            norm_ns, norm_name, _ = _split_namespace_and_name(
                purl_type=canonical_type,
                cleaned_name=parsed.name,
                explicit_namespace=parsed.namespace,
                osv_ecosystem=hinted_osv,
            )
            canonical_purl = str(
                PackageURL(type=canonical_type, namespace=norm_ns, name=norm_name).to_string()
            )
            resolved_eco = canonical_type
            resolved_ns = norm_ns
            if name is None:
                name = norm_name
            if version is None and parsed.version:
                version = clean_optional_str(parsed.version)
            distro_qualifier, upstream_package, upstream_version = extract_purl_os_qualifiers(
                purl_str
            )

    if name is None or version is None:
        return None

    try:
        return InventoryComponent(
            name=name,
            version=version,
            purl=purl_str,
            canonical_purl=canonical_purl,
            ecosystem=resolved_eco,
            namespace=resolved_ns,
            distro_qualifier=distro_qualifier,
            upstream_package=upstream_package,
            upstream_version=upstream_version,
            asset=asset,
            bom_ref=clean_optional_str(bom_ref),
        )
    except ValueError:
        return None


def derive_sbom_asset(
    data: Mapping[str, Any],
    *,
    asset_id: str,
    backend: str,
    location: str | None = None,
    scope: str | None = None,
    asset_type: str | None = None,
    extra_metadata: Mapping[str, Any] | None = None,
) -> AssetRef:
    """Construct a cloud-agnostic :class:`AssetRef` enriched from SBOM document headers.

    Args:
        data: Parsed CycloneDX or SPDX JSON mapping.
        asset_id: Unique asset identifier (file path, object URI, digest, or resource ID).
        backend: Registered ``zerobom.backends`` name owning the asset.
        location: Optional path, URI, digest, or region string.
        scope: Optional scope override; falls back to document root component or doc name.
        asset_type: Optional asset category override; falls back to metadata component type or
            ``"sbom"``.
        extra_metadata: Optional plugin-supplied opaque metadata merged safely into ``metadata``.

    Returns:
        Validated :class:`AssetRef`.

    Raises:
        SbomParseError: If required asset fields violate :class:`AssetRef` validation.
    """
    raw_meta: dict[str, Any] = {}
    inferred_type: str | None = None
    inferred_scope: str | None = None

    if is_cyclonedx_document(data):
        metadata = data.get("metadata")
        meta_comp = metadata.get("component") if isinstance(metadata, Mapping) else None
        if isinstance(meta_comp, Mapping):
            inferred_type = clean_optional_str(meta_comp.get("type"))
            inferred_scope = clean_optional_str(meta_comp.get("name"))
        raw_meta = {
            "format": "cyclonedx",
            "spec_version": data.get("specVersion"),
            "serial_number": data.get("serialNumber"),
        }
    elif is_spdx_document(data):
        inferred_scope = clean_optional_str(data.get("name")) or clean_optional_str(
            data.get("SPDXID")
        )
        raw_meta = {
            "format": "spdx",
            "spdx_version": data.get("spdxVersion"),
            "document_namespace": data.get("documentNamespace"),
        }

    if extra_metadata:
        raw_meta = {**raw_meta, **extra_metadata}

    try:
        return AssetRef(
            asset_id=asset_id,
            asset_type=clean_optional_str(asset_type) or inferred_type or "sbom",
            backend=backend,
            scope=clean_optional_str(scope) or inferred_scope,
            location=clean_optional_str(location),
            metadata=build_safe_metadata(raw_meta),
        )
    except (ValidationError, ValueError) as exc:
        raise SbomParseError(f"Invalid asset metadata for {asset_id}: {exc}") from exc


def parse_cyclonedx_dict(
    data: Mapping[str, Any],
    *,
    asset: AssetRef,
    source_label: str = "<sbom>",
    max_depth: int = MAX_CYCLONEDX_DEPTH,
) -> tuple[InventoryComponent, ...]:
    """Parse a CycloneDX (1.4-1.6) JSON mapping iteratively with bounded recursion depth.

    Args:
        data: Decoded CycloneDX JSON object.
        asset: :class:`AssetRef` attached to every extracted component.
        source_label: Human-readable label included in depth-limit diagnostics.
        max_depth: Maximum nested ``components[]`` traversal depth permitted.

    Returns:
        Tuple of normalized :class:`InventoryComponent` entries.

    Raises:
        ValueError: If ``max_depth < 1``.
        SbomParseError: If nesting exceeds ``max_depth``.
    """
    if max_depth < 1:
        raise ValueError("max_depth must be >= 1")

    metadata = data.get("metadata")
    meta_comp = metadata.get("component") if isinstance(metadata, Mapping) else None

    components: list[InventoryComponent] = []
    # Traverse component tree iteratively using an explicit stack to prevent stack overflow.
    stack: list[tuple[Mapping[str, Any], int]] = []

    if isinstance(meta_comp, Mapping):
        stack.append((meta_comp, 0))

    top_components = data.get("components")
    if isinstance(top_components, list):
        # Push in reverse so popped order preserves original document order.
        for item in reversed(top_components):
            if isinstance(item, Mapping):
                stack.append((item, 0))

    while stack:
        comp_dict, depth = stack.pop()
        if depth > max_depth:
            raise SbomParseError(
                f"CycloneDX component nesting in {source_label} exceeds max depth {max_depth}."
            )

        normalized = make_inventory_component(
            raw_name=comp_dict.get("name"),
            raw_version=comp_dict.get("version"),
            raw_purl=comp_dict.get("purl"),
            ecosystem_hint=None,
            namespace_hint=comp_dict.get("group"),
            asset=asset,
            bom_ref=comp_dict.get("bom-ref"),
        )
        if normalized is not None:
            components.append(normalized)

        children = comp_dict.get("components")
        if isinstance(children, list):
            for child in reversed(children):
                if isinstance(child, Mapping):
                    stack.append((child, depth + 1))

    return tuple(components)


def parse_spdx_dict(
    data: Mapping[str, Any],
    *,
    asset: AssetRef,
) -> tuple[InventoryComponent, ...]:
    """Parse an SPDX (2.2-2.3) JSON mapping into normalized components.

    Args:
        data: Decoded SPDX JSON object.
        asset: :class:`AssetRef` attached to every extracted component.

    Returns:
        Tuple of normalized :class:`InventoryComponent` entries.
    """
    components: list[InventoryComponent] = []
    packages = data.get("packages")
    if not isinstance(packages, list):
        return ()

    for pkg in packages:
        if not isinstance(pkg, Mapping):
            continue
        raw_ver = clean_optional_str(pkg.get("versionInfo"))
        if raw_ver is not None and raw_ver.upper() in _SPDX_MISSING_SENTINELS:
            raw_ver = None
        raw_purl = _extract_spdx_purl(pkg)

        normalized = make_inventory_component(
            raw_name=pkg.get("name"),
            raw_version=raw_ver,
            raw_purl=raw_purl,
            ecosystem_hint=None,
            namespace_hint=None,
            asset=asset,
            bom_ref=pkg.get("SPDXID"),
        )
        if normalized is not None:
            components.append(normalized)

    return tuple(components)


def parse_sbom_bytes(
    raw: bytes,
    *,
    asset_id: str,
    backend: str,
    location: str | None = None,
    scope: str | None = None,
    asset_type: str | None = None,
    extra_metadata: Mapping[str, Any] | None = None,
    max_bytes: int = MAX_SBOM_FILE_BYTES,
    max_depth: int = MAX_CYCLONEDX_DEPTH,
) -> tuple[InventoryComponent, ...]:
    """Decode and parse bounded UTF-8 CycloneDX or SPDX JSON bytes from any storage source.

    Args:
        raw: Unparsed UTF-8 JSON bytes representing a CycloneDX or SPDX document.
        asset_id: Unique asset identifier (file path, object URI, image digest, etc.).
        backend: Registered ``zerobom.backends`` plugin name.
        location: Optional manifest location or region string.
        scope: Optional project/cluster/bucket scope override.
        asset_type: Optional asset category override.
        extra_metadata: Optional extra metadata merged safely into the generated ``AssetRef``.
        max_bytes: Maximum allowed raw payload size prior to UTF-8/JSON decoding.
        max_depth: Maximum permitted nested CycloneDX component depth.

    Returns:
        Tuple of normalized :class:`InventoryComponent` entries.

    Raises:
        ValueError: If ``max_bytes < 1`` or ``max_depth < 1``.
        SbomParseError: If size exceeds ``max_bytes``, JSON is malformed, root is not a JSON
            object, or schema is neither CycloneDX nor SPDX 2.x.
    """
    if max_bytes < 1 or max_depth < 1:
        raise ValueError("max_bytes and max_depth must be >= 1")

    if len(raw) > max_bytes:
        raise SbomParseError(
            f"SBOM payload {asset_id} exceeds maximum size of {max_bytes} bytes ({len(raw)} bytes)."
        )

    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise SbomParseError(f"Invalid JSON in SBOM payload {asset_id}: {exc}") from exc

    if not isinstance(data, dict):
        raise SbomParseError(f"SBOM root in {asset_id} must be a JSON object.")

    if not is_cyclonedx_document(data) and not is_spdx_document(data):
        raise SbomParseError(
            f"Unrecognized SBOM schema in {asset_id} (expected CycloneDX or SPDX 2.x JSON)."
        )

    asset = derive_sbom_asset(
        data,
        asset_id=asset_id,
        backend=backend,
        location=location,
        scope=scope,
        asset_type=asset_type,
        extra_metadata=extra_metadata,
    )
    if is_cyclonedx_document(data):
        return parse_cyclonedx_dict(data, asset=asset, source_label=asset_id, max_depth=max_depth)
    return parse_spdx_dict(data, asset=asset)


class InMemoryComponentIndex:
    """In-memory O(1) lookup index over normalized :class:`InventoryComponent` records."""

    def __init__(self, components: Iterable[InventoryComponent] = ()) -> None:
        """Initialize the index and ingest any initial component records."""
        self._components: list[InventoryComponent] = []
        self._by_canonical_purl: dict[str, list[InventoryComponent]] = {}
        self._by_upstream_purl: dict[str, list[InventoryComponent]] = {}
        self._fallback_by_name: dict[str, list[InventoryComponent]] = {}
        if components:
            self.add_components(components)

    @property
    def components(self) -> tuple[InventoryComponent, ...]:
        """All indexed :class:`InventoryComponent` records in insertion order."""
        return tuple(self._components)

    def add_components(self, components: Iterable[InventoryComponent]) -> None:
        """Add normalized components into canonical PURL, upstream, and fallback indices."""
        for comp in components:
            self._components.append(comp)
            if comp.canonical_purl is not None:
                self._by_canonical_purl.setdefault(comp.canonical_purl, []).append(comp)
                if comp.upstream_package is not None:
                    up_purl = _build_upstream_canonical(comp.canonical_purl, comp.upstream_package)
                    if up_purl is not None:
                        self._by_upstream_purl.setdefault(up_purl, []).append(comp)
            else:
                lower_name = comp.name.strip().lower()
                pep503_name = _normalize_pep503(lower_name)
                keys = {lower_name, pep503_name}
                if comp.namespace is not None:
                    ns_lower = comp.namespace.strip().lower()
                    keys.add(f"{ns_lower}:{lower_name}")
                    keys.add(f"{ns_lower}/{lower_name}")
                for key in keys:
                    self._fallback_by_name.setdefault(key, []).append(comp)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Return deduplicated candidate components matching any supplied query.

        Args:
            queries: Canonical package descriptors built from an OSV advisory.

        Returns:
            Deduplicated tuple of matching :class:`InventoryComponent` objects.
        """
        matched: list[InventoryComponent] = []
        seen_ids: set[int] = set()

        def _collect(bucket: Sequence[InventoryComponent]) -> None:
            for comp in bucket:
                obj_id = id(comp)
                if obj_id not in seen_ids:
                    seen_ids.add(obj_id)
                    matched.append(comp)

        for query in queries:
            _collect(self._by_canonical_purl.get(query.canonical_purl, ()))
            _collect(self._by_upstream_purl.get(query.canonical_purl, ()))

            q_name_lower = query.name.lower()
            if (
                query.namespace is not None
                and query.ecosystem in {"maven", "npm", "golang", "composer"}
                and len(query.name) > 1
            ):
                ns_lower = query.namespace.lower()
                _collect(self._fallback_by_name.get(f"{ns_lower}:{q_name_lower}", ()))
                _collect(self._fallback_by_name.get(f"{ns_lower}/{q_name_lower}", ()))
            elif len(query.name) > 1 and q_name_lower not in GENERIC_PACKAGE_BLOCKLIST:
                _collect(self._fallback_by_name.get(q_name_lower, ()))
                if query.ecosystem == "pypi":
                    _collect(self._fallback_by_name.get(_normalize_pep503(q_name_lower), ()))
                if query.namespace is not None:
                    ns_lower = query.namespace.lower()
                    _collect(self._fallback_by_name.get(f"{ns_lower}:{q_name_lower}", ()))
                    _collect(self._fallback_by_name.get(f"{ns_lower}/{q_name_lower}", ()))

        return tuple(matched)
