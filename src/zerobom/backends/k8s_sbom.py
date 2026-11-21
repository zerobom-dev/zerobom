"""Read-only Kubernetes Trivy Operator ``SbomReport`` inventory backend."""

from __future__ import annotations

import base64
import json
import os
import re
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import httpx
import yaml

from zerobom.backends._http import (
    DEFAULT_API_TIMEOUT_SECONDS,
    DEFAULT_MAX_RESPONSE_BYTES,
    MAX_API_TIMEOUT_SECONDS,
    MAX_API_URL_LENGTH,
    REDIRECT_STATUS_CODES,
    parse_bool_opt,
    parse_float_opt,
    parse_int_opt,
    parse_optional_str_opt,
    read_bounded_response,
    reject_unknown_config_keys,
    resolve_tls_verify,
    validate_api_base_url,
    validate_bounded_int,
    validate_no_control_chars,
    validate_timeout_seconds,
)
from zerobom.backends.base import BackendConfigError, BackendQueryError
from zerobom.backends.sbom_parser import (
    MAX_CYCLONEDX_DEPTH,
    InMemoryComponentIndex,
    SbomParseError,
    build_safe_metadata,
    clean_optional_str,
    is_spdx_document,
    parse_cyclonedx_dict,
    parse_spdx_dict,
)
from zerobom.models import AssetRef, InventoryComponent, PackageQuery

_K8S_NAMESPACE_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_MAX_KUBECONFIG_BYTES = 2 * 1024 * 1024
_MAX_PEM_BYTES = 1024 * 1024
_TRIVY_GROUP_VERSION = "aquasecurity.github.io/v1alpha1"
_SA_TOKEN_DEFAULT = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_SA_CA_DEFAULT = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

_ALLOWED_CONFIG_KEYS: frozenset[str] = frozenset(
    {
        "api_server",
        "kubeconfig",
        "context",
        "cluster_name",
        "namespace",
        "include_cluster_reports",
        "label_selector",
        "bearer_token",
        "token_file",
        "username",
        "password",
        "ca_bundle",
        "verify_tls",
        "allow_insecure_http",
        "in_cluster",
        "page_size",
        "max_pages",
        "timeout_seconds",
        "max_response_bytes",
    }
)


def _read_bounded_secret_file(path: Path, *, field_name: str, max_bytes: int = 64 * 1024) -> str:
    """Read a UTF-8 credential/token file within strict byte bounds."""
    try:
        stat = path.stat()
    except OSError as exc:
        raise BackendConfigError(f"Cannot access {field_name} file {path}: {exc}") from exc
    if not path.is_file():
        raise BackendConfigError(f"Configured {field_name} path is not a file: {path}")
    if stat.st_size > max_bytes:
        raise BackendConfigError(
            f"Configured {field_name} file {path} exceeds limit of {max_bytes} bytes."
        )
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise BackendConfigError(f"Failed to read {field_name} file {path}: {exc}") from exc
    # Strip trailing newlines on mounted ServiceAccount tokens while keeping internal checks.
    return validate_no_control_chars(
        raw.rstrip("\r\n"), field_name=field_name, max_length=max_bytes
    )


def _decode_base64_pem(raw_b64: Any, *, field_name: str) -> bytes:
    """Decode bounded base64 PEM material from kubeconfig fields (allows RFC 2045 line wraps)."""
    if not isinstance(raw_b64, str):
        raise BackendConfigError(f"Configuration option {field_name!r} must be a string.")
    if any((ord(ch) < 32 and ch not in "\r\n\t") or ord(ch) == 127 for ch in raw_b64):
        raise BackendConfigError(
            f"Configuration option {field_name!r} must not contain control characters."
        )
    compact = raw_b64.replace("\r", "").replace("\n", "").replace("\t", "").replace(" ", "")
    max_b64_len = (_MAX_PEM_BYTES * 4) // 3 + 16
    if not compact:
        raise BackendConfigError(f"Configuration option {field_name!r} must not be empty.")
    if len(compact) > max_b64_len:
        raise BackendConfigError(
            f"Configuration option {field_name!r} exceeds maximum length of {max_b64_len} chars."
        )
    try:
        decoded = base64.b64decode(compact, validate=True)
    except ValueError as exc:
        raise BackendConfigError(
            f"Invalid base64 data in kubeconfig {field_name!r}: {exc}"
        ) from exc
    if len(decoded) > _MAX_PEM_BYTES or not decoded.strip():
        raise BackendConfigError(f"Invalid or oversized PEM payload in kubeconfig {field_name!r}.")
    return decoded


def _find_named_entry(
    entries: Any,
    target_name: str,
    *,
    section: str,
    value_key: str,
) -> Mapping[str, Any]:
    """Locate a named object inside a kubeconfig list (clusters/contexts/users)."""
    if not isinstance(entries, list):
        raise BackendConfigError(f"Kubeconfig section {section!r} must be a list.")
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if entry.get("name") == target_name:
            inner = entry.get(value_key)
            if isinstance(inner, Mapping):
                return inner
            raise BackendConfigError(
                f"Kubeconfig {section!r} entry {target_name!r} is missing {value_key!r}."
            )
    raise BackendConfigError(f"Kubeconfig {section!r} entry {target_name!r} was not found.")


def _resolve_kubeconfig_path_field(raw_path: Any, *, base_dir: Path, field_name: str) -> Path:
    """Resolve an external file referenced inside kubeconfig relative to its directory."""
    cleaned = validate_no_control_chars(raw_path, field_name=field_name, max_length=2048)
    candidate = Path(cleaned)
    if not candidate.is_absolute():
        candidate = (base_dir / candidate).resolve()
    if not candidate.is_file():
        raise BackendConfigError(
            f"Kubeconfig {field_name!r} file does not exist or is not a file: {candidate}"
        )
    return candidate


class K8sSbomBackend:
    """Read-only Kubernetes API backend querying Trivy Operator ``SbomReport`` CRDs."""

    def __init__(
        self,
        *,
        api_server: str | None = None,
        kubeconfig: str | Path | None = None,
        context: str | None = None,
        cluster_name: str | None = None,
        namespace: str | None = None,
        include_cluster_reports: bool = False,
        label_selector: str | None = None,
        bearer_token: str | None = None,
        token_file: str | Path | None = None,
        username: str | None = None,
        password: str | None = None,
        ca_bundle: str | Path | None = None,
        ca_pem_data: str | None = None,
        client_cert: str | Path | None = None,
        client_key: str | Path | None = None,
        in_cluster: bool = False,
        serviceaccount_token_path: str | Path = _SA_TOKEN_DEFAULT,
        serviceaccount_ca_path: str | Path = _SA_CA_DEFAULT,
        env: Mapping[str, str] | None = None,
        page_size: int = 100,
        max_pages: int = 50,
        verify_tls: bool = True,
        allow_insecure_http: bool = False,
        timeout_seconds: float = DEFAULT_API_TIMEOUT_SECONDS,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        http_client: httpx.Client | None = None,
    ) -> None:
        """Initialize a read-only Kubernetes Trivy Operator ``SbomReport`` backend.

        Supports explicit ``api_server`` + credentials, standard ``kubeconfig`` YAML files
        (excluding ``exec`` credential plugins), and in-cluster ServiceAccount discovery.

        Raises:
            BackendConfigError: If cluster discovery, auth, TLS, namespace, or bounds fail.
        """
        if not isinstance(include_cluster_reports, bool):
            raise BackendConfigError(
                "Configuration option 'include_cluster_reports' must be a bool."
            )
        if not isinstance(in_cluster, bool):
            raise BackendConfigError("Configuration option 'in_cluster' must be a bool.")
        if not isinstance(verify_tls, bool):
            raise BackendConfigError("Configuration option 'verify_tls' must be a bool.")
        if not isinstance(allow_insecure_http, bool):
            raise BackendConfigError("Configuration option 'allow_insecure_http' must be a bool.")

        self._page_size = validate_bounded_int(
            page_size, field_name="page_size", min_value=1, max_value=500
        )
        self._max_pages = validate_bounded_int(
            max_pages, field_name="max_pages", min_value=1, max_value=500
        )
        self._timeout_seconds = validate_timeout_seconds(timeout_seconds)
        self._max_response_bytes = validate_bounded_int(
            max_response_bytes,
            field_name="max_response_bytes",
            min_value=1024,
            max_value=100 * 1024 * 1024,
        )

        if namespace is not None:
            cleaned_ns = validate_no_control_chars(namespace, field_name="namespace", max_length=63)
            if not _K8S_NAMESPACE_RE.fullmatch(cleaned_ns):
                raise BackendConfigError(
                    f"Invalid Kubernetes namespace {namespace!r}; must match DNS-1123 label."
                )
            self._namespace: str | None = cleaned_ns
        else:
            self._namespace = None

        self._label_selector: str | None = (
            validate_no_control_chars(label_selector, field_name="label_selector", max_length=512)
            if label_selector is not None
            else None
        )
        self._include_cluster_reports = include_cluster_reports
        self._index: InMemoryComponentIndex | None = None

        if (username is None) != (password is None):
            raise BackendConfigError("Both 'username' and 'password' must be provided together.")

        env_map = env if env is not None else os.environ

        resolved_server: str | None = (
            validate_api_base_url(
                api_server,
                allow_insecure_http=allow_insecure_http,
                field_name="api_server",
            )
            if api_server is not None
            else None
        )
        resolved_cluster_name: str | None = (
            validate_no_control_chars(cluster_name, field_name="cluster_name", max_length=128)
            if cluster_name is not None
            else None
        )
        resolved_token: str | None = (
            validate_no_control_chars(bearer_token, field_name="bearer_token", max_length=8192)
            if bearer_token is not None
            else None
        )
        if resolved_token is None and token_file is not None:
            tf_path = Path(
                validate_no_control_chars(str(token_file), field_name="token_file", max_length=2048)
            )
            resolved_token = _read_bounded_secret_file(tf_path, field_name="token_file")

        resolved_user: str | None = (
            validate_no_control_chars(username, field_name="username", max_length=512)
            if username is not None
            else None
        )
        resolved_pass: str | None = (
            validate_no_control_chars(password, field_name="password", max_length=4096)
            if password is not None
            else None
        )
        resolved_ca_bundle: str | Path | None = ca_bundle
        resolved_ca_pem: str | None = ca_pem_data
        resolved_client_cert: str | Path | None = client_cert
        resolved_client_key: str | Path | None = client_key
        client_cert_bytes: bytes | None = None
        client_key_bytes: bytes | None = None

        kubeconfig_candidate: Path | None = None
        if kubeconfig is not None:
            kc_str = validate_no_control_chars(
                str(kubeconfig), field_name="kubeconfig", max_length=2048
            )
            kubeconfig_candidate = Path(kc_str)
        elif not in_cluster and resolved_server is None:
            raw_kc_env = env_map.get("KUBECONFIG")
            if raw_kc_env and raw_kc_env.strip():
                first_kc = raw_kc_env.split(os.pathsep)[0]
                kubeconfig_candidate = Path(
                    validate_no_control_chars(first_kc, field_name="KUBECONFIG", max_length=2048)
                )

        if kubeconfig_candidate is not None:
            (
                kc_server,
                kc_cluster,
                kc_token,
                kc_user,
                kc_pass,
                kc_ca_bundle,
                kc_ca_pem,
                kc_cert_path,
                kc_key_path,
                kc_cert_bytes,
                kc_key_bytes,
            ) = self._load_kubeconfig(
                kubeconfig_candidate,
                context_name=context,
                verify_tls=verify_tls,
                allow_insecure_http=allow_insecure_http,
            )
            if resolved_server is None:
                resolved_server = kc_server
            if resolved_cluster_name is None:
                resolved_cluster_name = kc_cluster
            if resolved_token is None:
                resolved_token = kc_token
            if resolved_user is None and resolved_pass is None:
                resolved_user = kc_user
                resolved_pass = kc_pass
            if resolved_ca_bundle is None and resolved_ca_pem is None:
                resolved_ca_bundle = kc_ca_bundle
                resolved_ca_pem = kc_ca_pem
            if resolved_client_cert is None and resolved_client_key is None:
                if kc_cert_path is not None and kc_key_path is not None:
                    resolved_client_cert = kc_cert_path
                    resolved_client_key = kc_key_path
                elif kc_cert_bytes is not None and kc_key_bytes is not None:
                    client_cert_bytes = kc_cert_bytes
                    client_key_bytes = kc_key_bytes
        elif in_cluster or resolved_server is None:
            sa_server, sa_token, sa_ca = self._load_in_cluster(
                env_map=env_map,
                token_path=Path(serviceaccount_token_path),
                ca_path=Path(serviceaccount_ca_path),
                allow_insecure_http=allow_insecure_http,
                require_token=(resolved_token is None and resolved_user is None),
            )
            if resolved_server is None:
                resolved_server = sa_server
            if resolved_token is None:
                resolved_token = sa_token
            if resolved_ca_bundle is None and resolved_ca_pem is None and sa_ca is not None:
                resolved_ca_bundle = sa_ca
            if resolved_cluster_name is None:
                resolved_cluster_name = "in-cluster"

        if resolved_server is None:
            raise BackendConfigError(
                "K8sSbomBackend could not determine a Kubernetes API server; supply 'api_server', "
                "'kubeconfig', KUBECONFIG, or in-cluster ServiceAccount environment variables."
            )

        self._api_server = resolved_server
        self._cluster_name = resolved_cluster_name or "default"
        self._bearer_token = resolved_token
        self._username = resolved_user
        self._password = resolved_pass

        if http_client is not None:
            if client_cert_bytes is not None and client_key_bytes is not None and not verify_tls:
                raise BackendConfigError(
                    "Cannot combine verify_tls=False with client certificate authentication."
                )
            self._client = http_client
            self._owns_client = False
        else:
            if client_cert_bytes is not None and client_key_bytes is not None:
                if not verify_tls:
                    raise BackendConfigError(
                        "Cannot combine verify_tls=False with client certificate authentication."
                    )
                with tempfile.TemporaryDirectory() as tmp_dir:
                    cert_tmp = Path(tmp_dir) / "client.crt"
                    key_tmp = Path(tmp_dir) / "client.key"
                    cert_tmp.write_bytes(client_cert_bytes)
                    key_tmp.write_bytes(client_key_bytes)
                    verify_arg = resolve_tls_verify(
                        verify_tls=verify_tls,
                        ca_bundle=resolved_ca_bundle,
                        ca_pem_data=resolved_ca_pem,
                        client_cert=cert_tmp,
                        client_key=key_tmp,
                    )
            else:
                verify_arg = resolve_tls_verify(
                    verify_tls=verify_tls,
                    ca_bundle=resolved_ca_bundle,
                    ca_pem_data=resolved_ca_pem,
                    client_cert=resolved_client_cert,
                    client_key=resolved_client_key,
                )

            self._client = httpx.Client(
                timeout=self._timeout_seconds,
                verify=verify_arg,
                follow_redirects=False,
            )
            self._owns_client = True

    @classmethod
    def from_config(cls, config: Mapping[str, Any]) -> K8sSbomBackend:
        """Instantiate :class:`K8sSbomBackend` from CLI options or YAML/JSON config."""
        reject_unknown_config_keys(config, _ALLOWED_CONFIG_KEYS, backend_name="k8s_sbom")

        return cls(
            api_server=parse_optional_str_opt(config, "api_server", max_length=MAX_API_URL_LENGTH),
            kubeconfig=parse_optional_str_opt(config, "kubeconfig", max_length=2048),
            context=parse_optional_str_opt(config, "context", max_length=128),
            cluster_name=parse_optional_str_opt(config, "cluster_name", max_length=128),
            namespace=parse_optional_str_opt(config, "namespace", max_length=63),
            include_cluster_reports=parse_bool_opt(
                config, "include_cluster_reports", default=False
            ),
            label_selector=parse_optional_str_opt(config, "label_selector", max_length=512),
            bearer_token=parse_optional_str_opt(
                config, "bearer_token", env_var="ZEROBOM_K8S_TOKEN", max_length=8192
            ),
            token_file=parse_optional_str_opt(config, "token_file", max_length=2048),
            username=parse_optional_str_opt(config, "username", max_length=512),
            password=parse_optional_str_opt(config, "password", max_length=4096),
            ca_bundle=parse_optional_str_opt(config, "ca_bundle", max_length=2048),
            verify_tls=parse_bool_opt(config, "verify_tls", default=True),
            allow_insecure_http=parse_bool_opt(config, "allow_insecure_http", default=False),
            in_cluster=parse_bool_opt(config, "in_cluster", default=False),
            page_size=parse_int_opt(config, "page_size", default=100, min_value=1, max_value=500),
            max_pages=parse_int_opt(config, "max_pages", default=50, min_value=1, max_value=500),
            timeout_seconds=parse_float_opt(
                config,
                "timeout_seconds",
                default=DEFAULT_API_TIMEOUT_SECONDS,
                min_value=0.5,
                max_value=MAX_API_TIMEOUT_SECONDS,
            ),
            max_response_bytes=parse_int_opt(
                config,
                "max_response_bytes",
                default=DEFAULT_MAX_RESPONSE_BYTES,
                min_value=1024,
                max_value=100 * 1024 * 1024,
            ),
        )

    @property
    def name(self) -> str:
        """Registered backend plugin identifier (``"k8s_sbom"``)."""
        return "k8s_sbom"

    def close(self) -> None:
        """Close the internally managed HTTP client connection pool."""
        if self._owns_client:
            self._client.close()

    def __repr__(self) -> str:
        """Return a redacted representation that never leaks Kubernetes credentials."""
        return (
            f"K8sSbomBackend(cluster={self._cluster_name!r}, "
            f"namespace={self._namespace!r}, api_server={self._api_server!r})"
        )

    def load(self) -> int:
        """Fetch and index Trivy Operator ``SbomReport`` objects into memory."""
        urls: list[str] = []
        if self._namespace is not None:
            urls.append(
                f"{self._api_server}/apis/{_TRIVY_GROUP_VERSION}/"
                f"namespaces/{self._namespace}/sbomreports"
            )
        else:
            urls.append(f"{self._api_server}/apis/{_TRIVY_GROUP_VERSION}/sbomreports")
        if self._include_cluster_reports:
            urls.append(f"{self._api_server}/apis/{_TRIVY_GROUP_VERSION}/clustersbomreports")

        index = InMemoryComponentIndex()
        for url in urls:
            for item in self._fetch_paginated_list(url):
                index.add_components(self._parse_sbom_report_item(item))

        self._index = index
        return len(index.components)

    def find_components(self, queries: Sequence[PackageQuery]) -> tuple[InventoryComponent, ...]:
        """Search indexed Kubernetes ``SbomReport`` components for candidate matches."""
        if not queries:
            return ()
        if self._index is None:
            self.load()
        if self._index is None:
            return ()
        return self._index.find_components(queries)

    def _load_kubeconfig(
        self,
        kubeconfig_path: Path,
        *,
        context_name: str | None,
        verify_tls: bool,
        allow_insecure_http: bool,
    ) -> tuple[
        str,
        str,
        str | None,
        str | None,
        str | None,
        Path | None,
        str | None,
        Path | None,
        Path | None,
        bytes | None,
        bytes | None,
    ]:
        """Parse kubeconfig YAML safely via ``yaml.safe_load`` without subprocess ``exec``."""
        try:
            stat = kubeconfig_path.stat()
        except OSError as exc:
            raise BackendConfigError(f"Cannot read kubeconfig {kubeconfig_path}: {exc}") from exc
        if not kubeconfig_path.is_file():
            raise BackendConfigError(f"Kubeconfig path is not a file: {kubeconfig_path}")
        if stat.st_size > _MAX_KUBECONFIG_BYTES:
            raise BackendConfigError(
                f"Kubeconfig {kubeconfig_path} exceeds maximum size of "
                f"{_MAX_KUBECONFIG_BYTES} bytes."
            )

        try:
            raw_yaml = kubeconfig_path.read_text(encoding="utf-8")
            parsed = yaml.safe_load(raw_yaml)
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
            raise BackendConfigError(
                f"Failed to parse kubeconfig YAML {kubeconfig_path}: {exc}"
            ) from exc

        if not isinstance(parsed, Mapping):
            raise BackendConfigError(f"Kubeconfig {kubeconfig_path} root must be a YAML mapping.")

        selected_context = context_name or clean_optional_str(parsed.get("current-context"))
        if selected_context is None:
            raise BackendConfigError(
                f"Kubeconfig {kubeconfig_path} has no current-context and no context specified."
            )

        ctx_map = _find_named_entry(
            parsed.get("contexts"),
            selected_context,
            section="contexts",
            value_key="context",
        )
        cluster_key = clean_optional_str(ctx_map.get("cluster"))
        if cluster_key is None:
            raise BackendConfigError(
                f"Kubeconfig context {selected_context!r} is missing a cluster name."
            )
        cluster_map = _find_named_entry(
            parsed.get("clusters"),
            cluster_key,
            section="clusters",
            value_key="cluster",
        )

        if cluster_map.get("insecure-skip-tls-verify") is True and verify_tls:
            raise BackendConfigError(
                f"Kubeconfig cluster {cluster_key!r} sets insecure-skip-tls-verify=true; "
                "pass explicit verify_tls=false to opt out of TLS verification."
            )

        server = validate_api_base_url(
            cluster_map.get("server"),
            allow_insecure_http=allow_insecure_http,
            field_name="kubeconfig cluster.server",
        )

        base_dir = kubeconfig_path.parent
        ca_bundle: Path | None = None
        ca_pem_data: str | None = None
        if cluster_map.get("certificate-authority") is not None:
            ca_bundle = _resolve_kubeconfig_path_field(
                cluster_map["certificate-authority"],
                base_dir=base_dir,
                field_name="certificate-authority",
            )
        elif cluster_map.get("certificate-authority-data") is not None:
            try:
                ca_pem_data = _decode_base64_pem(
                    cluster_map["certificate-authority-data"],
                    field_name="certificate-authority-data",
                ).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise BackendConfigError(
                    "Kubeconfig certificate-authority-data is not valid UTF-8 PEM."
                ) from exc

        token: str | None = None
        user_name_cred: str | None = None
        user_pass_cred: str | None = None
        cert_path: Path | None = None
        key_path: Path | None = None
        cert_bytes: bytes | None = None
        key_bytes: bytes | None = None

        user_key = clean_optional_str(ctx_map.get("user"))
        if user_key is not None and parsed.get("users"):
            user_map = _find_named_entry(
                parsed.get("users"),
                user_key,
                section="users",
                value_key="user",
            )
            if "exec" in user_map and user_map["exec"] is not None:
                raise BackendConfigError(
                    f"Kubeconfig user {user_key!r} configures an external 'exec' plugin; "
                    "subprocess credential execution is disabled for security. Supply "
                    "'bearer_token', 'token_file', or client certificates instead."
                )
            if user_map.get("token") is not None:
                token = validate_no_control_chars(
                    user_map["token"], field_name="kubeconfig user.token", max_length=8192
                )
            elif user_map.get("tokenFile") is not None:
                tf = _resolve_kubeconfig_path_field(
                    user_map["tokenFile"],
                    base_dir=base_dir,
                    field_name="kubeconfig user.tokenFile",
                )
                token = _read_bounded_secret_file(tf, field_name="kubeconfig tokenFile")

            if user_map.get("username") is not None and user_map.get("password") is not None:
                user_name_cred = validate_no_control_chars(
                    user_map["username"], field_name="kubeconfig user.username", max_length=512
                )
                user_pass_cred = validate_no_control_chars(
                    user_map["password"], field_name="kubeconfig user.password", max_length=4096
                )

            if (
                user_map.get("client-certificate") is not None
                and user_map.get("client-key") is not None
            ):
                cert_path = _resolve_kubeconfig_path_field(
                    user_map["client-certificate"],
                    base_dir=base_dir,
                    field_name="client-certificate",
                )
                key_path = _resolve_kubeconfig_path_field(
                    user_map["client-key"],
                    base_dir=base_dir,
                    field_name="client-key",
                )
            elif (
                user_map.get("client-certificate-data") is not None
                and user_map.get("client-key-data") is not None
            ):
                cert_bytes = _decode_base64_pem(
                    user_map["client-certificate-data"],
                    field_name="client-certificate-data",
                )
                key_bytes = _decode_base64_pem(
                    user_map["client-key-data"],
                    field_name="client-key-data",
                )

        return (
            server,
            cluster_key,
            token,
            user_name_cred,
            user_pass_cred,
            ca_bundle,
            ca_pem_data,
            cert_path,
            key_path,
            cert_bytes,
            key_bytes,
        )

    def _load_in_cluster(
        self,
        *,
        env_map: Mapping[str, str],
        token_path: Path,
        ca_path: Path,
        allow_insecure_http: bool,
        require_token: bool,
    ) -> tuple[str | None, str | None, Path | None]:
        """Discover Kubernetes API server and ServiceAccount credentials inside a Pod."""
        raw_host = env_map.get("KUBERNETES_SERVICE_HOST")
        raw_port = env_map.get("KUBERNETES_SERVICE_PORT")
        if not raw_host or not raw_port:
            return None, None, None

        host = validate_no_control_chars(
            raw_host, field_name="KUBERNETES_SERVICE_HOST", max_length=255
        )
        port_str = validate_no_control_chars(
            raw_port, field_name="KUBERNETES_SERVICE_PORT", max_length=5
        )
        if not port_str.isdigit() or not 1 <= int(port_str) <= 65535:
            raise BackendConfigError(f"Invalid KUBERNETES_SERVICE_PORT value: {raw_port!r}.")

        formatted_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        server = validate_api_base_url(
            f"https://{formatted_host}:{port_str}",
            allow_insecure_http=allow_insecure_http,
            field_name="in-cluster api_server",
        )

        token: str | None = None
        if require_token or token_path.is_file():
            token = _read_bounded_secret_file(token_path, field_name="serviceaccount_token_path")

        resolved_ca: Path | None = ca_path if ca_path.is_file() else None
        return server, token, resolved_ca

    def _fetch_paginated_list(self, url: str) -> list[dict[str, Any]]:
        """Paginate through a Kubernetes CRD list endpoint using ``metadata.continue``."""
        headers: dict[str, str] = {"Accept": "application/json"}
        if self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        auth_pair = (
            (self._username, self._password)
            if self._bearer_token is None
            and self._username is not None
            and self._password is not None
            else None
        )

        items: list[dict[str, Any]] = []
        continue_token: str | None = None

        for _ in range(self._max_pages):
            params: dict[str, str] = {"limit": str(self._page_size)}
            if self._label_selector is not None:
                params["labelSelector"] = self._label_selector
            if continue_token is not None:
                params["continue"] = continue_token

            status, _, body = read_bounded_response(
                self._client,
                "GET",
                url,
                max_bytes=self._max_response_bytes,
                params=params,
                headers=headers,
                auth=auth_pair,
                backend_name=self.name,
            )

            self._check_response_status(status, url)
            page_doc = self._decode_list_json(body, url)

            raw_items = page_doc.get("items")
            if raw_items is not None and not isinstance(raw_items, list):
                raise BackendQueryError(
                    f"[{self.name}] Kubernetes list field 'items' must be a JSON array at {url}."
                )
            if isinstance(raw_items, list):
                for entry in raw_items:
                    if isinstance(entry, dict):
                        items.append(entry)

            raw_meta = page_doc.get("metadata")
            next_token = (
                clean_optional_str(raw_meta.get("continue"))
                if isinstance(raw_meta, Mapping)
                else None
            )
            if not next_token:
                return items
            continue_token = next_token

        raise BackendQueryError(
            f"[{self.name}] Kubernetes pagination exceeded max_pages={self._max_pages} at {url}."
        )

    def _check_response_status(self, status: int, url: str) -> None:
        """Fail closed on redirects, RBAC denials, missing CRDs, rate limits, and errors."""
        if status in REDIRECT_STATUS_CODES:
            raise BackendQueryError(
                f"[{self.name}] Unexpected HTTP redirect ({status}) from {url}; redirects disabled."
            )
        if status in (401, 403):
            raise BackendQueryError(
                f"[{self.name}] Kubernetes authentication or RBAC authorization denied "
                f"({status}) at {url}."
            )
        if status == 404:
            raise BackendQueryError(
                f"[{self.name}] Trivy Operator CRD endpoint not found (404) at {url}."
            )
        if status == 429:
            raise BackendQueryError(f"[{self.name}] Kubernetes API rate limited (429) at {url}.")
        if status != 200:
            raise BackendQueryError(
                f"[{self.name}] Kubernetes API returned unexpected status {status} at {url}."
            )

    def _decode_list_json(self, body: bytes, url: str) -> dict[str, Any]:
        """Decode UTF-8 JSON Kubernetes list object."""
        try:
            decoded = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
            raise BackendQueryError(
                f"[{self.name}] Malformed JSON response from Kubernetes API {url}: {exc}"
            ) from exc
        if not isinstance(decoded, dict):
            raise BackendQueryError(
                f"[{self.name}] Expected JSON object from Kubernetes API {url}."
            )
        return decoded

    def _parse_sbom_report_item(self, item: Mapping[str, Any]) -> tuple[InventoryComponent, ...]:
        """Extract normalized components and cloud-agnostic ``AssetRef`` from an SbomReport."""
        meta = item.get("metadata")
        meta_map: Mapping[str, Any] = meta if isinstance(meta, Mapping) else {}
        labels = meta_map.get("labels")
        label_map: Mapping[str, Any] = labels if isinstance(labels, Mapping) else {}

        ns_label = clean_optional_str(meta_map.get("namespace")) or "_cluster"
        report_name = clean_optional_str(meta_map.get("name")) or "unknown"
        uid = clean_optional_str(meta_map.get("uid"))

        # Sanitize URI path components to avoid traversal tokens in SARIF locations.
        safe_cluster = self._cluster_name.replace("..", "_").replace("\\", "/")
        safe_ns = ns_label.replace("..", "_").replace("\\", "/")
        safe_report = report_name.replace("..", "_").replace("\\", "/")

        report = item.get("report")
        if not isinstance(report, Mapping):
            return ()

        raw_comps = report.get("components")
        if raw_comps is None:
            return ()

        image_str = _format_report_image(report)
        asset_id = f"k8s://{safe_cluster}/{safe_ns}/sbomreport/{safe_report}"
        asset = AssetRef(
            asset_id=asset_id,
            asset_type="k8s_workload",
            backend=self.name,
            scope=f"{safe_cluster}/{safe_ns}",
            location=asset_id,
            metadata=build_safe_metadata(
                {
                    "cluster": safe_cluster,
                    "namespace": safe_ns,
                    "report_name": report_name,
                    "uid": uid,
                    "resource_kind": label_map.get("trivy-operator.resource.kind"),
                    "resource_name": label_map.get("trivy-operator.resource.name"),
                    "container_name": label_map.get("trivy-operator.container.name"),
                    "image": image_str,
                }
            ),
        )

        if isinstance(raw_comps, list):
            bom_dict: Mapping[str, Any] = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": raw_comps,
            }
            try:
                return parse_cyclonedx_dict(
                    bom_dict,
                    asset=asset,
                    source_label=asset_id,
                    max_depth=MAX_CYCLONEDX_DEPTH,
                )
            except SbomParseError as exc:
                raise BackendQueryError(
                    f"[{self.name}] Invalid CycloneDX tree in {asset_id}: {exc}"
                ) from exc

        if isinstance(raw_comps, Mapping):
            if is_spdx_document(raw_comps):
                return parse_spdx_dict(raw_comps, asset=asset)
            try:
                return parse_cyclonedx_dict(
                    raw_comps,
                    asset=asset,
                    source_label=asset_id,
                    max_depth=MAX_CYCLONEDX_DEPTH,
                )
            except SbomParseError as exc:
                raise BackendQueryError(
                    f"[{self.name}] Invalid CycloneDX tree in {asset_id}: {exc}"
                ) from exc

        return ()


def _format_report_image(report: Mapping[str, Any]) -> str | None:
    """Build a human-readable container image string from Trivy Operator report fields."""
    registry = report.get("registry")
    artifact = report.get("artifact")
    reg_server = (
        clean_optional_str(registry.get("server")) if isinstance(registry, Mapping) else None
    )
    if not isinstance(artifact, Mapping):
        return None
    repo = clean_optional_str(artifact.get("repository"))
    if repo is None:
        return None
    tag = clean_optional_str(artifact.get("tag"))
    digest = clean_optional_str(artifact.get("digest"))

    base = f"{reg_server}/{repo}" if reg_server else repo
    if tag and digest:
        return f"{base}:{tag}@{digest}"
    if tag:
        return f"{base}:{tag}"
    if digest:
        return f"{base}@{digest}"
    return base
