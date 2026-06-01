# posthog-tap

A tiny, zero-dependency local **PostHog ingestion sink + payload inspector**.

Point `posthog-js` (or any PostHog SDK) at this server instead of PostHog Cloud,
and every event the SDK *would* send is captured, decoded, and shown in a live
web UI — without ever touching a real PostHog project. It exists so you can:

- **Verify an analytics integration locally** — does init fire? are events
  captured with the right names and distinct ids?
- **Audit payloads for PII before they ship** — the UI flags any property that
  looks like an email, long free text, or a sensitive key name, and warns if a
  `distinct_id` looks like an email instead of a stable internal id.

It is the analytics analogue of [MailHog/Mailpit] for email or a Pub/Sub tap:
a throwaway local endpoint that makes invisible network traffic visible.

## Run

```bash
# Docker (published image)
docker run --rm -p 4000:4000 ghcr.io/kay-bos/posthog-tap:latest

# or from source (needs Node ≥ 18, no install step — zero deps)
node server.js
```

Then open <http://localhost:4000> for the inspector UI.

Point your SDK at it:

```ts
posthog.init("phc_anything", { api_host: "http://localhost:4000" });
```

The token can be any string — the tap doesn't validate it.

## Endpoints

| Method + path | Purpose |
|---|---|
| `POST /e/` `/i/v0/e/` `/batch/` `/capture/` `/track/` `/engage/` `/s/` | Capture events (returns `{"status":1}`) |
| `POST /decide/` `/flags/` | Returns a minimal SDK config so init succeeds (autocapture/replay off) |
| `GET /` | Web UI (auto-refreshing) |
| `GET /events.json` | Captured events as JSON (handy for test assertions) |
| `GET /healthz` | Liveness probe |
| `POST /reset` / `DELETE /events` | Clear the buffer |

It tolerantly decodes every PostHog body encoding: raw JSON, `{batch:[…]}`,
gzip (`Content-Encoding: gzip` or `?compression=gzip-js`), and the legacy
`data=<base64>` form transport. CORS is wide open so a browser SDK on any
localhost port can post to it.

## Config

| Env | Default | Meaning |
|---|---|---|
| `PORT` | `4000` | Listen port |
| `MAX_EVENTS` | `1000` | Ring-buffer size (oldest dropped) |

Events are in-memory only — restart to clear.

## License

MIT
