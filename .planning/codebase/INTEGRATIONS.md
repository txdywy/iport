# External Integrations

**Analysis Date:** 2026-04-22

## APIs & External Services

**Networking:**
- Not applicable - Tool operates by sending raw packets and performing standard socket connections/handshakes.

## Data Storage

**Databases:**
- None - The tool is an ephemeral CLI scanner and does not persist data.

**File Storage:**
- Local filesystem only.

**Caching:**
- None.

## Authentication & Identity

**Auth Provider:**
- None - No user identity management or external auth required.

## Monitoring & Observability

**Error Tracking:**
- Standard Go `os.Stderr` logging and `error` returns.

**Logs:**
- Console output via `github.com/fatih/color`.

## CI/CD & Deployment

**Hosting:**
- Compiled binary - CLI tool.

**CI Pipeline:**
- None detected.

## Environment Configuration

**Required env vars:**
- None.

**Secrets location:**
- Not applicable.

## Webhooks & Callbacks

**Incoming:**
- None.

**Outgoing:**
- None.

---

*Integration audit: 2026-04-22*
