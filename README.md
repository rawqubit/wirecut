# wirecut

[![CI](https://github.com/rawqubit/wirecut/actions/workflows/ci.yml/badge.svg)](https://github.com/rawqubit/wirecut/actions/workflows/ci.yml) [![release](https://img.shields.io/github/v/release/rawqubit/wirecut?color=ffa53d)](https://github.com/rawqubit/wirecut/releases) [![license](https://img.shields.io/badge/license-MIT-56d3a6)](https://github.com/rawqubit/wirecut/blob/main/LICENSE)

A zero-dependency, HTTP/1.1 and HTTPS-intercepting debugging proxy written in pure Go (standard library only).

`wirecut` replaces Burp Suite, Charles, or Proxyman for the everyday 80% workflow: inspecting TLS API calls from CLI tools or local services, blocking or rewriting headers on the fly, saving clean JSON Lines session logs with sensitive headers redacted by default, and replaying edited requests from an embedded web UI.

## Install in one line

Prebuilt binaries for Linux, macOS and Windows on amd64 and arm64 — no Go toolchain needed:

```bash
curl -L https://github.com/rawqubit/wirecut/releases/download/v0.1.0/wirecut_v0.1.0_linux_amd64.tar.gz | tar -xz
./wirecut demo
```

macOS: swap `linux_amd64` for `darwin_arm64` (or `darwin_amd64`). Windows: take the `.zip` from [releases](https://github.com/rawqubit/wirecut/releases) and run `wirecut.exe`. Every archive has a SHA-256 in `checksums.txt`. Building from source is one `go build`, and it always works — but it should not be the first thing you have to do.

## What it does

- **On-the-fly MITM TLS:** Generates a local ECDSA P-256 root CA under `~/.wirecut/` (`ca.pem` + `ca-key.pem`) on first run and mints per-host leaf certificates (DNS SANs and IP SANs) dynamically for `CONNECT` tunnels.
- **HTTP/1.1 & HTTPS proxy:** Forwards plain HTTP and MITM-decrypted HTTPS traffic while preserving methods, URLs, headers, and full request/response bodies on the wire, capping recorded body capture at `--max-body`.
- **Redacted JSONL session logs:** Persists every exchange as JSON Lines with timestamps, millisecond duration, wire sizes, truncation flags, and redacted copies of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, and `X-Api-Key` headers by default (pass `--no-redact` to record raw values).
- **Rule engine:** Loads rules from `--rules <file.json>` or repeatable `--rule` flags to block requests by host/path/method and add or strip request/response headers before forwarding.
- **Embedded web UI (`--ui :8099`):** Self-contained single-page app (`//go:embed`, zero external assets) with a live Server-Sent Events stream, host/path/method/status/rule filtering, pretty-printed JSON bodies, header inspection, and one-click request replay with edited headers routed back through the proxy.

## Honest limits

- **HTTP/1.1 only:** ALPN negotiates `http/1.1` only; there is no HTTP/2 or HTTP/3 support.
- **No WebSocket framing:** `Upgrade: websocket` and bidirectional frame inspection are not implemented.
- **No Intruder/fuzzer or scanner:** Replay sends a single edited request at a time; there is no payload fuzzing or passive vulnerability scanner yet.
- **Not a security boundary:** `wirecut` is a local developer debugging tool. `~/.wirecut/ca-key.pem` is stored unencrypted (`0600`) for convenience, and default redaction scrubs standard credential headers (`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`) rather than scanning arbitrary URLs or JSON bodies for secrets.

## Install

Requires Go 1.25+ (zero external modules):

```sh
git clone https://github.com/rawqubit/wirecut.git
cd wirecut
go build -o wirecut .
```

## Commands

### 1. `wirecut proxy`

Starts the intercepting proxy (default `:8080`), embedded web UI (default `:8099`), CA initialization, and JSONL session recorder:

```sh
./wirecut proxy \
  --listen :8080 \
  --ui :8099 \
  --rules rules.json \
  --session session.jsonl \
  --max-body 1048576
```

Flags:
- `--listen` (default `:8080`) — proxy listen address
- `--ui` (default `:8099`) — web UI listen address (`""` to disable)
- `--ca-dir` (default `~/.wirecut`) — directory for `ca.pem` and `ca-key.pem`
- `--session` (default `~/.wirecut/sessions/session-<timestamp>.jsonl`) — JSONL session output path
- `--rules` — path to a JSON rules file
- `--rule` — repeatable inline rule (JSON object or shorthand `block:host=...,path=...,method=...,status=403`)
- `--max-body` (default `1048576`) — maximum request/response body bytes stored per exchange
- `--no-redact` — write raw sensitive headers to the session log instead of `[REDACTED]`
- `--insecure` — skip upstream TLS certificate verification (useful for local self-signed servers)

Test it with `curl` trusting the generated CA:

```sh
curl -x http://127.0.0.1:8080 --cacert ~/.wirecut/ca.pem https://example.com/
```

Example `rules.json`:

```json
{
  "rules": [
    {
      "name": "block-admin-delete",
      "match": { "host": "api.local", "path": "/admin/*", "method": "DELETE" },
      "action": "block",
      "status": 403,
      "body": "Blocked by wirecut\n"
    },
    {
      "name": "inject-trace",
      "match": { "host": "*.local", "path": "/api/*" },
      "action": "rewrite",
      "set_request_headers": { "X-Debug-Proxy": "wirecut" },
      "remove_response_headers": ["X-Powered-By"]
    }
  ]
}
```

### 2. `wirecut demo`

Runs a completely self-contained, offline headless scenario: starts an ephemeral MITM CA, an in-process TLS server (with its own certificate) and HTTP server, a proxy with blocking/rewrite rules and a 512-byte capture cap, drives 6 requests through the proxy, verifies zero raw secrets hit disk, and writes a JSONL session file:

```sh
./wirecut demo --session /tmp/wirecut-demo.jsonl
```

Real output:

```text
wirecut demo
  CA:       wirecut Local Root CA (ephemeral MITM CA)
  Proxy:    http://127.0.0.1:45221 (HTTP/1.1 + CONNECT MITM)
  Upstream: https://127.0.0.1:46479 (in-process TLS) + http://127.0.0.1:41413 (HTTP)
  Rules:    block-admin-delete, inject-trace-and-strip
  Cap:      512 bytes | Redact: true | Session: /tmp/wirecut-demo.jsonl

  [1/6] GET    http  /api/health            -> 200  (  37 B wire)  plain HTTP health check [proxy-hdr:intercepted]
  [2/6] GET    https /api/users             -> 200  (  66 B wire)  HTTPS GET with header rewrite [proxy-hdr:intercepted]
  [3/6] POST   https /api/orders            -> 201  ( 106 B wire)  HTTPS JSON POST with redacted secrets [proxy-hdr:intercepted]
  [4/6] PUT    https /api/orders/42         -> 200  (  46 B wire)  HTTPS JSON PUT [proxy-hdr:intercepted]
  [5/6] DELETE https /api/admin/reset       -> 403  (  56 B wire)  HTTPS DELETE blocked by rule [blocked:block-admin-delete]
  [6/6] GET    https /api/blob              -> 200  (2048 B wire)  HTTPS large body (> capture cap) [proxy-hdr:intercepted]

Summary:
  Exchanges recorded: 6 (blocked=1, truncated=1)
  Upstream saw blocked DELETE: false
  Raw secrets on disk: false
  Session file: /tmp/wirecut-demo.jsonl (5196 bytes)
```

### 3. `wirecut ui`

Serves the embedded web inspector offline against a previously saved JSONL session file (optionally pointing `--proxy` at a running `wirecut proxy` instance to enable Replay):

```sh
./wirecut ui --ui :8099 --session /tmp/wirecut-demo.jsonl
```

## Tests

All tests run offline with no network access:

```sh
go test -race -v ./...
```

## Author

Srinikhil Chakilam — [MIT License](LICENSE)
