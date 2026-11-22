"""Shared bounded S3 prefix loading, gzip decompression, and Inspector2 enrichment."""

from __future__ import annotations

import json
import re
import zlib
from collections.abc import Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from zerobom.backends import (
    BackendConfigError,
    BackendQueryError,
    InMemoryComponentIndex,
    SbomParseError,
    parse_sbom_bytes,
)
from zerobom.backends._http import validate_no_control_chars
from zerobom.backends.sbom_parser import (
    clean_optional_str,
    is_cyclonedx_document,
    is_spdx_document,
)
from zerobom.models import InventoryComponent

S3_BUCKET_RE = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
DEFAULT_SBOM_SUFFIXES: tuple[str, ...] = (
    ".json",
    ".cdx.json",
    ".spdx.json",
    ".json.gz",
    ".cdx.json.gz",
    ".spdx.json.gz",
)
ARCHIVED_S3_STORAGE_CLASSES: frozenset[str] = frozenset({"GLACIER", "DEEP_ARCHIVE"})
_DECOMPRESS_CHUNK_BYTES = 65536


def validate_s3_bucket(bucket: str) -> str:
    """Validate an Amazon S3 bucket name against AWS naming rules."""
    cleaned = validate_no_control_chars(bucket, field_name="bucket", max_length=63)
    if ".." in cleaned or not S3_BUCKET_RE.fullmatch(cleaned):
        raise BackendConfigError(f"Invalid S3 bucket name: {bucket!r}.")
    return cleaned


def validate_s3_prefix(prefix: str) -> str:
    """Validate an S3 key prefix against control characters and traversal segments."""
    cleaned = validate_no_control_chars(
        prefix, field_name="prefix", max_length=1024, allow_empty=True
    )
    if "\\" in cleaned or any(seg == ".." for seg in cleaned.split("/")):
        raise BackendConfigError(
            f"S3 prefix {prefix!r} must not contain backslashes or '..' traversal segments."
        )
    return cleaned


def matches_sbom_suffix(key: str, suffixes: Sequence[str]) -> bool:
    """Return True if ``key`` ends with any configured suffix (or suffixes is empty)."""
    if not suffixes:
        return True
    lower = key.lower()
    return any(lower.endswith(suf) for suf in suffixes)


def maybe_decompress_sbom_bytes(
    raw: bytes,
    *,
    object_label: str,
    content_encoding: str | None,
    max_bytes: int,
    backend_name: str,
) -> bytes:
    """Stream-decompress gzip SBOM bytes while strictly enforcing ``max_bytes``."""
    has_gzip_magic = raw[:2] == b"\x1f\x8b"
    expects_gzip = object_label.lower().endswith(".gz") or (
        content_encoding is not None and "gzip" in content_encoding.lower()
    )
    already_plain_json = not has_gzip_magic and raw.lstrip()[:1] in (b"{", b"[")
    if not has_gzip_magic and (not expects_gzip or already_plain_json):
        if len(raw) > max_bytes:
            raise BackendQueryError(
                f"[{backend_name}] S3 object {object_label} exceeds limit {max_bytes} bytes."
            )
        return raw

    decomp = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = bytearray()
    try:
        for offset in range(0, len(raw), _DECOMPRESS_CHUNK_BYTES):
            chunk = raw[offset : offset + _DECOMPRESS_CHUNK_BYTES]
            remaining = max_bytes - len(out)
            piece = decomp.decompress(chunk, max_length=remaining + 1)
            out.extend(piece)
            if len(out) > max_bytes or decomp.unconsumed_tail:
                raise BackendQueryError(
                    f"[{backend_name}] Decompressed SBOM {object_label} exceeds "
                    f"limit {max_bytes} bytes."
                )
        if not decomp.eof:
            raise SbomParseError(f"Truncated gzip stream in SBOM {object_label}.")
        remaining = max_bytes - len(out)
        tail = decomp.flush(remaining + 1)
        out.extend(tail)
    except BackendQueryError:
        raise
    except zlib.error as exc:
        raise SbomParseError(f"Corrupt gzip SBOM stream in {object_label}: {exc}") from exc

    if len(out) > max_bytes:
        raise BackendQueryError(
            f"[{backend_name}] Decompressed SBOM {object_label} exceeds limit {max_bytes} bytes."
        )
    return bytes(out)


def extract_inspector_asset_overrides(
    raw_bytes: bytes,
) -> tuple[str | None, str | None, str | None, str | None, dict[str, str]]:
    """Inspect decoded JSON SBOM headers for Amazon Inspector2 resource provenance."""
    try:
        doc = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return None, None, None, None, {}
    if not isinstance(doc, Mapping):
        return None, None, None, None, {}

    if is_cyclonedx_document(doc):
        metadata = doc.get("metadata")
        if not isinstance(metadata, Mapping):
            return None, None, None, None, {}

        props_map: dict[str, str] = {}
        raw_props = metadata.get("properties")
        if isinstance(raw_props, list):
            for prop in raw_props:
                if not isinstance(prop, Mapping):
                    continue
                k = clean_optional_str(prop.get("name"))
                v = clean_optional_str(prop.get("value"))
                if k is not None and v is not None:
                    props_map[k] = v

        has_inspector_marker = any(key.startswith("amazon:inspector:") for key in props_map) or (
            "imageId" in props_map and ("awsAccountId" in props_map or "accountId" in props_map)
        )
        if not has_inspector_marker:
            tools = metadata.get("tools")
            if isinstance(tools, list):
                has_inspector_marker = any(
                    isinstance(t, Mapping)
                    and "inspector" in (clean_optional_str(t.get("name")) or "").lower()
                    for t in tools
                )
        if not has_inspector_marker:
            return None, None, None, None, {}

        meta_comp = metadata.get("component")
        comp_name = (
            clean_optional_str(meta_comp.get("name")) if isinstance(meta_comp, Mapping) else None
        )
        comp_type = (
            clean_optional_str(meta_comp.get("type")) if isinstance(meta_comp, Mapping) else None
        )

        asset_id = (
            props_map.get("amazon:inspector:sbom_generator:resource_id")
            or props_map.get("resourceId")
            or props_map.get("imageId")
            or comp_name
        )
        asset_type = (
            props_map.get("amazon:inspector:sbom_generator:resource_type")
            or props_map.get("resourceType")
            or comp_type
            or "aws_inspector_resource"
        )
        scope = (
            props_map.get("amazon:inspector:sbom_generator:account_id")
            or props_map.get("accountId")
            or props_map.get("awsAccountId")
        )
        location = (
            props_map.get("amazon:inspector:sbom_generator:region")
            or props_map.get("region")
            or props_map.get("awsRegion")
        )
        extra: dict[str, str] = {}
        if "imageId" in props_map:
            extra["image_id"] = props_map["imageId"]
        return asset_id, asset_type, scope, location, extra

    if is_spdx_document(doc):
        creation_info = doc.get("creationInfo")
        creators = creation_info.get("creators") if isinstance(creation_info, Mapping) else None
        has_inspector_creator = isinstance(creators, list) and any(
            isinstance(c, str) and "inspector" in c.lower() for c in creators
        )
        if not has_inspector_creator:
            return None, None, None, None, {}
        doc_name = clean_optional_str(doc.get("name"))
        if doc_name is not None:
            return doc_name, "aws_inspector_resource", None, None, {}

    return None, None, None, None, {}


def _download_bounded_s3_object(
    client: Any,
    *,
    bucket: str,
    key: str,
    backend_name: str,
    max_sbom_bytes: int,
    expected_bucket_owner: str | None,
    skip_archived: bool,
) -> tuple[bytes, str | None] | None:
    """Download a single S3 object safely; returns ``None`` if skipped archived state."""
    get_kwargs: dict[str, Any] = {"Bucket": bucket, "Key": key}
    if expected_bucket_owner is not None:
        get_kwargs["ExpectedBucketOwner"] = expected_bucket_owner

    try:
        resp = client.get_object(**get_kwargs)
    except ClientError as exc:
        err_code = str(exc.response.get("Error", {}).get("Code", ""))
        if err_code == "InvalidObjectState" and skip_archived:
            return None
        raise BackendQueryError(
            f"[{backend_name}] S3 GetObject failed for s3://{bucket}/{key}: {exc}"
        ) from exc
    except BotoCoreError as exc:
        raise BackendQueryError(
            f"[{backend_name}] S3 GetObject failed for s3://{bucket}/{key}: {exc}"
        ) from exc

    content_length = resp.get("ContentLength")
    if isinstance(content_length, int) and content_length > max_sbom_bytes:
        body = resp.get("Body")
        if body is not None and callable(getattr(body, "close", None)):
            body.close()
        raise BackendQueryError(
            f"[{backend_name}] S3 object s3://{bucket}/{key} ContentLength "
            f"({content_length} bytes) exceeds limit {max_sbom_bytes}."
        )

    body = resp.get("Body")
    if body is None or not callable(getattr(body, "read", None)):
        raise BackendQueryError(
            f"[{backend_name}] S3 GetObject returned empty body stream for {key!r}."
        )
    try:
        raw = body.read(max_sbom_bytes + 1)
    except (OSError, BotoCoreError, ClientError) as exc:
        raise BackendQueryError(
            f"[{backend_name}] Failed reading S3 body for {key!r}: {exc}"
        ) from exc
    finally:
        if callable(getattr(body, "close", None)):
            body.close()

    if not isinstance(raw, bytes) or len(raw) > max_sbom_bytes:
        raise BackendQueryError(
            f"[{backend_name}] S3 object s3://{bucket}/{key} exceeds limit {max_sbom_bytes} bytes."
        )

    content_encoding = clean_optional_str(resp.get("ContentEncoding"))
    return raw, content_encoding


def load_s3_sbom_prefix(
    client: Any,
    *,
    bucket: str,
    prefix: str,
    suffixes: Sequence[str],
    backend_name: str,
    max_objects: int,
    max_pages: int,
    max_sbom_bytes: int,
    strict: bool,
    skip_archived: bool = True,
    expected_bucket_owner: str | None = None,
    max_concurrency: int = 8,
    extra_base_metadata: Mapping[str, Any] | None = None,
) -> InMemoryComponentIndex:
    """List, download, decompress, parse, and deterministically index S3 SBOM objects."""
    entries: list[tuple[str, int | None, str | None]] = []
    continuation_token: str | None = None
    completed = False

    for _ in range(max_pages):
        kwargs: dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
        if continuation_token is not None:
            kwargs["ContinuationToken"] = continuation_token
        if expected_bucket_owner is not None:
            kwargs["ExpectedBucketOwner"] = expected_bucket_owner

        try:
            resp = client.list_objects_v2(**kwargs)
        except (ClientError, BotoCoreError) as exc:
            raise BackendQueryError(
                f"[{backend_name}] S3 ListObjectsV2 failed on s3://{bucket}/{prefix}: {exc}"
            ) from exc

        contents = resp.get("Contents")
        if isinstance(contents, list):
            for obj in contents:
                if not isinstance(obj, Mapping):
                    continue
                key = clean_optional_str(obj.get("Key"))
                if key is None or not matches_sbom_suffix(key, suffixes):
                    continue
                if any(seg == ".." for seg in key.split("/")):
                    raise BackendQueryError(
                        f"[{backend_name}] Disallowed traversal segment in S3 key {key!r}."
                    )
                storage_class = (clean_optional_str(obj.get("StorageClass")) or "").upper()
                if storage_class in ARCHIVED_S3_STORAGE_CLASSES:
                    if skip_archived:
                        continue
                    raise BackendQueryError(
                        f"[{backend_name}] S3 object s3://{bucket}/{key} resides in archived "
                        f"storage class {storage_class}."
                    )
                size = obj.get("Size")
                etag = clean_optional_str(obj.get("ETag"))
                entries.append(
                    (
                        key,
                        size if isinstance(size, int) and not isinstance(size, bool) else None,
                        etag,
                    )
                )
                if len(entries) > max_objects:
                    raise BackendQueryError(
                        f"[{backend_name}] Matching S3 SBOM objects exceeded "
                        f"max_objects={max_objects}."
                    )

        if not bool(resp.get("IsTruncated")):
            completed = True
            break
        continuation_token = clean_optional_str(resp.get("NextContinuationToken"))
        if continuation_token is None:
            completed = True
            break

    if not completed:
        raise BackendQueryError(
            f"[{backend_name}] S3 ListObjectsV2 pagination exceeded max_pages={max_pages}."
        )

    for key, declared_size, _ in entries:
        if declared_size is not None and declared_size > max_sbom_bytes:
            raise BackendQueryError(
                f"[{backend_name}] S3 object s3://{bucket}/{key} declares size "
                f"{declared_size} > limit {max_sbom_bytes} bytes."
            )

    def _process_entry(
        entry: tuple[str, int | None, str | None],
    ) -> tuple[InventoryComponent, ...]:
        key, _, etag = entry
        downloaded = _download_bounded_s3_object(
            client,
            bucket=bucket,
            key=key,
            backend_name=backend_name,
            max_sbom_bytes=max_sbom_bytes,
            expected_bucket_owner=expected_bucket_owner,
            skip_archived=skip_archived,
        )
        if downloaded is None:
            return ()
        raw_bytes, content_encoding = downloaded
        s3_uri = f"s3://{bucket}/{key}"
        try:
            plain_bytes = maybe_decompress_sbom_bytes(
                raw_bytes,
                object_label=s3_uri,
                content_encoding=content_encoding,
                max_bytes=max_sbom_bytes,
                backend_name=backend_name,
            )
            ov_asset_id, ov_asset_type, ov_scope, ov_location, ov_meta = (
                extract_inspector_asset_overrides(plain_bytes)
            )
            merged_meta: dict[str, Any] = {
                "bucket": bucket,
                "key": key,
                "etag": etag,
                "s3_uri": s3_uri,
            }
            if extra_base_metadata:
                merged_meta.update(extra_base_metadata)
            merged_meta.update(ov_meta)

            return parse_sbom_bytes(
                plain_bytes,
                asset_id=ov_asset_id or s3_uri,
                backend=backend_name,
                location=ov_location or s3_uri,
                scope=ov_scope or bucket,
                asset_type=ov_asset_type,
                extra_metadata=merged_meta,
                max_bytes=max_sbom_bytes,
            )
        except SbomParseError as exc:
            if strict:
                raise BackendQueryError(
                    f"[{backend_name}] Failed to parse S3 SBOM {s3_uri}: {exc}"
                ) from exc
            return ()

    index = InMemoryComponentIndex()
    if max_concurrency > 1 and len(entries) > 1:
        ordered: list[tuple[InventoryComponent, ...] | None] = [None] * len(entries)
        with ThreadPoolExecutor(max_workers=min(max_concurrency, len(entries))) as pool:
            future_to_idx: dict[Future[tuple[InventoryComponent, ...]], int] = {
                pool.submit(_process_entry, entry): idx for idx, entry in enumerate(entries)
            }
            try:
                for fut in as_completed(future_to_idx):
                    idx = future_to_idx[fut]
                    ordered[idx] = fut.result()
            except Exception:
                for pending in future_to_idx:
                    pending.cancel()
                raise
        for comps in ordered:
            if comps:
                index.add_components(comps)
    else:
        for entry in entries:
            comps = _process_entry(entry)
            if comps:
                index.add_components(comps)

    return index
