# Hedr — Project Status

_Last updated: 2026-09-18_

Repo: https://github.com/kjayavardhan02/Hedr
Stack: Next.js 15 + TypeScript (frontend) · Python + FastAPI + SQLite (backend) · Gemini (AI explanations)

---

## ✅ Done — V1 (per `Hedr/Hedr_Idea.md` section 20)

| Feature | Status |
|---|---|
| URL input scanning | ✅ |
| Raw HTTP response input scanning | ✅ |
| Header parser | ✅ |
| Custom policies (create/edit/delete, persisted in SQLite) | ✅ |
| Built-in baselines (Basic, Strict, SaaS, Fintech) — clone-to-customize | ✅ |
| Deterministic rule engine — presence, exact-value, allowed-values (`a\|b\|c`), directive-aware comparison (HSTS `max-age`, Permissions-Policy) | ✅ |
| Dedicated CSP analyzer — policy compliance + always-on best-practice checks (wildcards, `unsafe-inline`/`unsafe-eval`, missing `object-src`/`base-uri`/`frame-ancestors`) | ✅ |
| Weighted security score + letter grade | ✅ |
| AI explanations & remediation recommendations (Gemini, on-demand per finding, per-check before/after fixes) | ✅ |
| SSRF-guarded URL fetching (blocks private/loopback/link-local addresses) | ✅ |

### Also done, beyond the bare V1 checklist

- Full responsive UI: black/orange theme, animated score ring, toasts, skeleton loading, copy-to-clipboard, smooth expand/collapse, hover/press feedback
- Back-navigation on policy pages, uniform policy-card layout
- Git repo initialized and pushed to GitHub, with SSH deploy key configured (no token needed for future pushes)
- `README.md` — full setup + usage guide for new users

### Hardening pass (post-V1 review)

- Request size limits on scan/explain inputs (prevents oversized-payload abuse)
- URL fetcher streams responses instead of buffering full bodies (headers-only, avoids memory/DoS risk on large responses)
- Explicit timeout on the Gemini API call (prevents indefinite hangs)
- **DNS-rebinding gap in the SSRF guard closed** — `fetcher.py` used to validate a hostname's resolved IP, then hand the *hostname* back to httpx, which re-resolved DNS itself on connect; a very-short-TTL DNS response could have resolved to a private IP in that window. Now `_validate_url` returns the validated IP itself, and `fetch_headers` connects directly to that pinned IP (never re-resolving), while still sending the original hostname as the `Host` header and TLS SNI so certificate validation and virtual hosting work exactly as before. Verified against live HTTPS sites (including a cross-scheme redirect) and against the existing SSRF-blocked cases (loopback, link-local, `169.254.169.254`, `localhost`) — all still correctly blocked/allowed.

### Automated test suite (backend) — was the biggest gap, now closed

- 118 pytest tests, 94% statement coverage on `backend/app` (`pytest --cov=app`)
- Pure-logic unit tests: `comparators.py`, `header_parser.py`, `csp_analyzer.py`,
  `scoring.py`, `policy_engine.py` (incl. HSTS `max-age` numeric comparison,
  Permissions-Policy allowlist matching, CSP best-practice checks, score/grade
  boundaries)
- SSRF-guard unit tests for `fetcher.py` — blocked IP ranges (private, loopback,
  link-local, multicast, IPv4-mapped IPv6), scheme/hostname validation, DNS
  resolution failure, and redirect-chain re-validation, all via mocked
  `socket.getaddrinfo`/`httpx.Client` (no real network calls)
- API tests (FastAPI `TestClient`) for all three routers: `/api/policies`
  (CRUD + baseline-immutability rules), `/api/scan` (raw + URL sources, error
  paths), `/api/explain` (503/502/200 paths, AI client mocked)
- Tests run against a throwaway temp SQLite file (`app/database.py` now reads
  `DATABASE_URL` from env, defaulting to the real `hedr.db` path) — never
  touches the real dev database
- Found and fixed one real bug while writing tests: `_is_blocked_ip()` in
  `fetcher.py` could return `None` instead of `False` for non-IPv4-mapped
  IPv6 addresses (falsy either way at the call site, so not exploitable, but
  a real type/correctness bug)
- Run with: `cd backend && pip install -r requirements-dev.txt && pytest`
  (see README's "Running the backend tests" section)
- **Not yet done:** no frontend tests, and no CI wiring to run this suite
  automatically on push (still listed below under "Hardening still
  outstanding")

---

## ⏳ Not done — known gaps

### V2 (deferred, per your instruction — not started)

- Multiple applications / multi-target tracking
- Scheduled scans
- Security regression detection (diff scans over time)
- Historical scan results (currently only **policies** persist — scans do not)
- Notifications (Slack/email on regression)
- Team accounts / multi-user

### Hardening still outstanding

- **No frontend tests** — backend now has a pytest suite (see above), but the Next.js frontend has none yet.
- **No rate limiting** on `/api/scan` or `/api/explain` (the latter costs real money per call)
- **AI prompt-injection surface** — a malicious scanned site controls its own header values, which flow into the AI explanation prompt. Can't affect the PASS/FAIL verdict or score (already computed deterministically before AI runs), but could theoretically try to influence the explanation *text*. Not sanitized against this.
- No authentication — anyone who can reach the backend can manage policies and spend AI quota. Fine on localhost only.
- No CI pipeline (lint/type-check/test-on-push)
- No DB migrations (Alembic) — fine at SQLite/hobby scale
- No structured logging/observability beyond uvicorn's default access log
- `npm audit` flags a moderate/high `postcss` advisory in Next's build tooling (dev-time only, not shipped to users) — fixing it means a Next.js major-version bump I didn't want to make unasked

### Product-spec items not implemented

- Finding IDs (spec's `HSTS-003`-style identifiers) — findings currently have severity/status/checks/recommendation but no stable ID field

### Deployment

- **Not deployed anywhere** — runs locally only (`localhost:3000` frontend, `127.0.0.1:8123` backend). Decided to defer deployment; recommendation when ready is Render (not Vercel — Vercel's serverless model doesn't fit the FastAPI + SQLite backend well).

---

## Current state

Both dev servers are stopped. To run locally again: see `README.md` → "Getting started".
