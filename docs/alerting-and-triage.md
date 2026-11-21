# Alerting & Human-in-the-Loop Triage

`zerobom` enforces a strict noise policy across webhooks, Slack, and CLI workflows:

| Routing Decision | Composite Score | Outbound Behavior |
| --- | --- | --- |
| **`AUTO`** | `>= 0.75` | Queries inventory automatically; emits consolidated alert **only when vulnerable hits > 0**. |
| **`TRIAGE`** | `0.50 – 0.74` | Emits human review notification showing verified quote + approve/reject controls; never alerts inventory hits until approved. |
| **`DROP`** | `< 0.50` | Suppressed silently (`0` outbound webhook/Slack HTTP calls). |

## Generic HTTPS Webhooks (`--webhook-url`)

Send consolidated JSON payloads signed with HMAC-SHA256 headers (`X-Zerobom-Timestamp` + `X-Zerobom-Signature`):

```bash
zerobom watch \
  --feeds sources.yaml \
  --sbom ./sboms/ \
  --webhook-url https://alerts.example.org/hooks/zerobom \
  --webhook-secret "$ZEROBOM_WEBHOOK_SECRET"
```

Security properties enforced by [`WebhookNotifier`](api/outputs.md):
- Enforces HTTPS (unless internal loopback/private targets are explicitly opted in via `--allow-private-webhook` for internal relays).
- Re-validates DNS resolution right before outbound POSTs to prevent DNS-rebinding TOCTOU attacks.
- Disables HTTP redirects (`follow_redirects=False`) and scrubs webhook paths, query parameters, and tokens from errors and `__repr__`.

## Slack Block Kit Alerts (`--slack-webhook-url`)

Posts structured Slack Block Kit cards to pinned Slack webhook hosts (`hooks.slack.com`, `hooks.slack-gov.com`) with `<`, `>`, `&` escaping, backtick neutralization, capped section length (`<= 2950` chars), and interactive **Approve & Scan** / **Reject** action buttons for `TRIAGE` advisories.

## Persistent Triage Queue & Interactive Approval

Persist pending advisories in SQLite (`--triage-db`) with per-channel notification deduplication:

```bash
# List queued advisories safely (Rich markup escaped)
zerobom triage list --triage-db .zerobom/triage.sqlite

# Inspect advisory evidence quote and compiled OSV metadata
zerobom triage show PRECVE-2026-7DA3A045 --triage-db .zerobom/triage.sqlite

# Approve (acquires per-ID lock, runs deterministic inventory scan, alerts if hits > 0)
zerobom triage approve PRECVE-2026-7DA3A045 \
  --triage-db .zerobom/triage.sqlite \
  --sbom ./sboms/ \
  --actor secops-oncall

# Reject without scanning or alerting
zerobom triage reject PRECVE-2026-7DA3A045 \
  --triage-db .zerobom/triage.sqlite \
  --actor secops-oncall \
  --note "Not affected"
```

### Signed Slack Callback Worker (`zerobom triage-worker`)

Run the zero-dependency HTTP callback receiver (default loopback `127.0.0.1:8787`) behind your TLS reverse proxy or use optional Slack Socket Mode (`pip install "zerobom[slack]"`):

```bash
# Signed HTTP callback mode (verifies X-Slack-Signature HMAC & 300s replay window; <3s ack)
zerobom triage-worker \
  --transport http \
  --host 127.0.0.1 \
  --port 8787 \
  --signing-secret "$ZEROBOM_SLACK_SIGNING_SECRET" \
  --triage-db .zerobom/triage.sqlite \
  --sbom ./sboms/

# Optional Socket Mode (no inbound firewall port required; requires slack-sdk)
zerobom triage-worker \
  --transport socket-mode \
  --app-token "$ZEROBOM_SLACK_APP_TOKEN" \
  --bot-token "$ZEROBOM_SLACK_BOT_TOKEN" \
  --triage-db .zerobom/triage.sqlite \
  --sbom ./sboms/
```

The worker validates backend configuration upfront before opening sockets, limits concurrent POST handlers (`HTTP 503` backpressure), enforces socket read timeouts (`request_timeout_seconds`), serializes duplicate button clicks per triage ID, and sends asynchronous approval results or errors back to Slack's `response_url`.
