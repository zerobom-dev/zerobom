# Getting Started

## Installation & Zero-Config Demo

Run the offline demonstration immediately with `uvx` (zero API keys, zero network calls; always exits `0` for quick-start smoke verification):

```bash
uvx zerobom demo
```

Or install into a project or global tool environment:

```bash
# Core (cloud-agnostic CLI + local_sbom, dependency_track, oci_sbom, k8s_sbom)
uv tool install zerobom

# With optional Slack Socket Mode or cloud backend extras (cloud plugins publish via plugins-v* tags)
uv tool install "zerobom[aws,slack]"
```

Check the installed version and discovered plugins:

```bash
zerobom --version
zerobom backends
```

## CLI Modes

### 1. Deterministic OSV Scan (`zerobom scan`) — Zero LLM

Match pre-compiled or official OSV JSON advisories against any inventory backend with deterministic exit codes (`0` clean, `1` vulnerable hits, `2` error):

```bash
zerobom scan \
  --osv advisory.osv.json \
  --sbom sbom.cdx.json \
  --format sarif \
  --sarif-out zerobom.sarif
```

Both `--json-out` and `--sarif-out` can be written simultaneously alongside `--format terminal`.

### 2. Single-Article Verification (`zerobom check`)

Fetch a single security blog advisory URL through the SSRF-hardened HTTP fetcher, extract candidate claims, verify quote grounding and package coordinates, and match your SBOM:

```bash
zerobom check \
  --url https://example.org/research/requests-pre-cve \
  --tier tier_1 \
  --source-name "Security Research Lab" \
  --verify-registry \
  --sbom sbom.cdx.json
```

By default, manual URLs start at `--tier unknown` (maximum composite score `0.55`, routing to `TRIAGE` for human review unless `--include-triage` is passed). Use `--triage-db .zerobom-triage.sqlite` to persist pending items.

### 3. Feed Polling (`zerobom watch`)

Poll curated RSS, Atom, XML sitemap, or HTML index security blogs defined in `sources.yaml`:

```bash
zerobom watch \
  --feeds sources.yaml \
  --sbom ./sboms/ \
  --state-db .zerobom/state.sqlite \
  --triage-db .zerobom/triage.sqlite \
  --format sarif \
  --sarif-out zerobom.sarif
```

HTTP `ETag` and `Last-Modified` conditional headers plus SHA-256 content digests ensure unchanged blog posts are skipped cleanly while edited advisories are re-verified.

## Configuring the LLM Extraction Layer

`zerobom` uses a lean OpenAI-compatible HTTP client (`OpenAICompatExtractor`) defaulting to local Ollama (`http://localhost:11434/v1`, model `llama3.2`) with `temperature=0.0`. Both `zerobom check` and `zerobom watch` read LLM settings from environment variables (`OpenAICompatConfig.from_env()`):

| Environment Variable | Default | Examples |
| --- | --- | --- |
| `ZEROBOM_LLM_BASE_URL` | `http://localhost:11434/v1` | `https://api.openai.com/v1`, `https://openrouter.ai/api/v1`, `https://generativelanguage.googleapis.com/v1beta/openai/` |
| `ZEROBOM_LLM_MODEL` | `llama3.2` | `gpt-4o-mini`, `qwen2.5:14b`, `gemini-2.5-flash` |
| `ZEROBOM_LLM_API_KEY` | `None` (also reads `OPENAI_API_KEY`) | Bearer token for hosted providers |

> **Important configuration behavior:**
> - `zerobom demo`, `zerobom scan`, `zerobom backends`, and `zerobom triage` require **zero LLM configuration**.
> - `zerobom` does **not** auto-load `.env` files — export these variables in your active shell (or configure them as CI secrets; see `.env.example` for reference names).
> - Setting `OPENAI_API_KEY` or `ZEROBOM_LLM_API_KEY` alone does **not** change the default `base_url` or `model` away from local Ollama (`http://localhost:11434/v1` and `llama3.2`). When using a hosted provider, set **all three** variables (`ZEROBOM_LLM_BASE_URL`, `ZEROBOM_LLM_MODEL`, and `ZEROBOM_LLM_API_KEY`).

### Local Models (Zero External Egress)

#### Option 1: Ollama (Default)

1. Install Ollama from [ollama.com](https://ollama.com/) and start the local service:

   ```bash
   ollama serve
   ```

   *(On Windows and macOS, launching the Ollama desktop app starts the background server on port `11434` automatically.)*

2. Pull a model (`llama3.2` matches the zero-config default; `qwen2.5:14b` improves structured JSON formatting and verbatim quote copying):

   ```bash
   ollama pull llama3.2
   # Optional: higher accuracy if your hardware has ~10+ GB VRAM/RAM
   # ollama pull qwen2.5:14b
   ```

3. Verify Ollama's OpenAI-compatible API is reachable:

   ```bash
   # Linux / macOS
   curl http://localhost:11434/v1/models
   ```

   ```powershell
   # Windows PowerShell
   Invoke-RestMethod http://localhost:11434/v1/models
   ```

4. Run `zerobom check` or `zerobom watch` with no API keys required:

   ```bash
   # Uses default http://localhost:11434/v1 and model llama3.2 automatically
   zerobom check --url https://example.org/research/requests-pre-cve --sbom sbom.cdx.json
   ```

   To switch to another pulled Ollama model:

   ```bash
   # Linux / macOS (Bash / zsh)
   export ZEROBOM_LLM_MODEL="qwen2.5:14b"
   zerobom watch --feeds sources.yaml --sbom ./sboms/
   ```

   ```powershell
   # Windows PowerShell
   $env:ZEROBOM_LLM_MODEL = "qwen2.5:14b"
   zerobom watch --feeds sources.yaml --sbom ./sboms/
   ```

#### Option 2: vLLM, LM Studio, or llama.cpp

Any local inference server exposing an OpenAI-compatible `POST <base_url>/chat/completions` endpoint works by setting `ZEROBOM_LLM_BASE_URL` and `ZEROBOM_LLM_MODEL` (leave `ZEROBOM_LLM_API_KEY` unset, or set it to `"local"` if the server requires an `Authorization` header):

- **vLLM** (`http://localhost:8000/v1`):

  ```bash
  export ZEROBOM_LLM_BASE_URL="http://localhost:8000/v1"
  export ZEROBOM_LLM_MODEL="Qwen/Qwen2.5-14B-Instruct"
  ```

- **LM Studio** (`http://localhost:1234/v1` — enable the **Local Server** tab in LM Studio and load an instruction-tuned model):

  ```bash
  export ZEROBOM_LLM_BASE_URL="http://localhost:1234/v1"
  export ZEROBOM_LLM_MODEL="<loaded-model-id>"
  ```

- **llama.cpp (`llama-server`)** (`http://localhost:8080/v1`):

  ```bash
  llama-server -m /path/to/model.gguf --port 8080

  # In another terminal:
  export ZEROBOM_LLM_BASE_URL="http://localhost:8080/v1"
  export ZEROBOM_LLM_MODEL="local"
  ```

> **JSON mode compatibility:** `OpenAICompatExtractor` sends `response_format={"type": "json_object"}` at `temperature=0.0` by default. Pick an instruction-tuned model/server that supports OpenAI JSON mode. If you embed `zerobom` via the Python API against a server that rejects `response_format`, configure `OpenAICompatConfig(use_json_response_format=False)`.

### Hosted OpenAI-Compatible Providers

Always set `ZEROBOM_LLM_BASE_URL`, `ZEROBOM_LLM_MODEL`, and `ZEROBOM_LLM_API_KEY` together in the active shell:

**OpenAI:**

```bash
# Linux / macOS (Bash / zsh)
export ZEROBOM_LLM_BASE_URL="https://api.openai.com/v1"
export ZEROBOM_LLM_MODEL="gpt-4o-mini"
export ZEROBOM_LLM_API_KEY="sk-..."

zerobom check --url https://example.org/research/requests-pre-cve --sbom sbom.cdx.json
```

```powershell
# Windows PowerShell
$env:ZEROBOM_LLM_BASE_URL = "https://api.openai.com/v1"
$env:ZEROBOM_LLM_MODEL    = "gpt-4o-mini"
$env:ZEROBOM_LLM_API_KEY  = "sk-..."

zerobom check --url https://example.org/research/requests-pre-cve --sbom sbom.cdx.json
```

**Other hosted OpenAI-compatible endpoints:**

- **OpenRouter:**

  ```bash
  export ZEROBOM_LLM_BASE_URL="https://openrouter.ai/api/v1"
  export ZEROBOM_LLM_MODEL="openai/gpt-4o-mini"
  export ZEROBOM_LLM_API_KEY="sk-or-..."
  ```

- **Google Gemini (OpenAI-compatible endpoint):**

  ```bash
  export ZEROBOM_LLM_BASE_URL="https://generativelanguage.googleapis.com/v1beta/openai/"
  export ZEROBOM_LLM_MODEL="gemini-2.5-flash"
  export ZEROBOM_LLM_API_KEY="AIza..."
  ```

> **Data egress note:** When using `zerobom check` or `zerobom watch` with a hosted endpoint (`ZEROBOM_LLM_BASE_URL`), fetched public article titles, URLs, and windowed article text (`<= 24` KB) are sent to that provider. Your SBOMs and software inventories are **never** transmitted to the LLM.
