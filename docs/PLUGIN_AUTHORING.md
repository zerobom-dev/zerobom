# Authoring `zerobom.backends` Inventory Plugins

`zerobom` discovers inventory backends through standard Python entry points in the **`zerobom.backends`** group (`importlib.metadata.entry_points(group="zerobom.backends")`). Core stays 100% cloud-agnostic while external or workspace plugins integrate arbitrary SBOM stores, dependency managers, container registries, and cloud inventories.

---

## 1. Contract Overview (`InventoryBackend`)

Every backend implements [`InventoryBackend`](api/backends.md):

```python
from collections.abc import Sequence
from zerobom.models import AssetRef, InventoryComponent, PackageQuery


class MyInventoryBackend:
    @property
    def name(self) -> str:
        return "my_backend"

    @classmethod
    def from_config(cls, config: dict[str, object]) -> "MyInventoryBackend": ...

    def find_components(
        self, queries: Sequence[PackageQuery]
    ) -> tuple[InventoryComponent, ...]: ...

    def close(self) -> None: ...
```

**Design Invariant:** Plugins **never** evaluate version ranges. Return normalized `InventoryComponent` records matching the package coordinates in `PackageQuery`; deterministic version math stays exclusively in `zerobom.verify.osv_compiler` (`univers`).

---

## 2. Registering via `pyproject.toml`

Add an entry point matching `^[a-z][a-z0-9_-]{0,63}$`:

```toml
[project.entry-points."zerobom.backends"]
my_backend = "zerobom_my_plugin.backend:MyInventoryBackend"
```

Verify discovery without importing until needed:

```bash
uv run zerobom backends
```

---

## 3. Configuration (`from_config`, `--backend-opt`, `--backend-config`)

The CLI parses YAML/JSON config files (`--backend-config`) and repeatable `--backend-opt KEY=VALUE` flags via `parse_backend_options()` and invokes `BackendRegistry.create(name, config=config)`.

- Implement `@classmethod def from_config(cls, config: Mapping[str, Any])` to validate options and read sensitive credentials (e.g., API tokens) from environment variables when not passed directly.
- Implement `close(self) -> None` if the backend owns HTTP/SDK sessions; the CLI registers `close()` inside `ExitStack` automatically.

---

## 4. Reusing Hardened SBOM Parsing & Indexing

If your plugin fetches CycloneDX (1.4–1.6) or SPDX (2.2–2.3) JSON payloads from object storage, container registries, or APIs, **do not write a custom parser**. Reuse `zerobom.backends`:

```python
from zerobom.backends import InMemoryComponentIndex, parse_sbom_bytes

components = parse_sbom_bytes(
    raw_bytes,
    asset_id=f"s3://{bucket}/{key}",
    backend=self.name,
    location=f"s3://{bucket}/{key}",
    extra_metadata={"etag": object_etag},
)
index = InMemoryComponentIndex(components)
```

`parse_sbom_bytes()` enforces payload byte limits prior to JSON decoding, nesting depth limits, ASCII control-character filtering, and `AssetRef` metadata ceilings (<= 32 entries, keys <= 64 chars, values <= 512 chars).

---

## 5. Error Handling & Security Standards

- **Never rely on bare `assert` in production code** (stripped under `python -O`).
- **Exception Hierarchy (`zerobom.backends`):**
  - Raise `BackendConfigError` on invalid or missing plugin options/credentials.
  - Raise `BackendQueryError` on upstream HTTP errors (401/403/429/5xx), timeouts, or pagination ceiling exhaustion so the CLI exits cleanly with code `2`.
- **Credential Hygiene:** Never expose API keys or tokens in `__repr__`, exceptions, logs, or `AssetRef.metadata`.
- **HTTP & Query Safety:** Enforce `https://` by default, set `follow_redirects=False`, validate URL path/query parameters cleanly, and enforce response-size and pagination bounds.

---

## 6. Running the Conformance Test Suite

Every plugin must pass [`assert_backend_conformance`](api/backends.md) in pytest using mocked SDK/HTTP clients (no live network calls in unit tests):

```python
from zerobom.backends import assert_backend_conformance, build_default_conformance_case


def test_my_backend_conformance(my_mocked_backend):
    case = build_default_conformance_case(
        backend_name="my_backend",
        package_name="requests",
        ecosystem="PyPI",
        canonical_purl="pkg:pypi/requests",
        vulnerable_fixed="2.31.0",  # installed fixture is 2.30.0
        safe_fixed="1.0.0",
    )
    matches = assert_backend_conformance(my_mocked_backend, case)
    assert len(matches) >= 1
```
