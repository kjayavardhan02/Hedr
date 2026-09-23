# Hedr — Features Pending / Postponed

_Last updated: 2026-09-23_

Things intentionally deferred, not yet started, or explicitly postponed per earlier instructions — not bugs in what's already built.

---

## V2 scope (deferred — not started)

- Multiple applications / multi-target tracking.
- Scheduled scans.
- Security regression detection (diffing scores/findings between scans over time) — scan history itself exists (Reports), but automatic diff/regression detection does not.
- Notifications (Slack/email on regression).
- Team accounts / multi-user (shared policies/reports across a team).

## CSP overhaul — judgment calls / follow-ups noted but not built

- `parser_warnings` field from the original CSP implementation plan — deferred; no current consumer needs it (would ripple into `CSPFinding`, frontend, and tests for no immediate payoff).
- No automated test coverage for the new frontend CSP components (`CSPPolicyBuilder`, `CSPPolicySummary`) — verified via manual browser smoke test only, consistent with the rest of the frontend (see "No frontend tests" below).

## Product-spec items not implemented

- Stable finding IDs for **generic (non-CSP) header findings** (e.g. an `HSTS-003`-style identifier) — CSP now has this (`CSP-000`–`CSP-014`), but regular header checks (HSTS, X-Content-Type-Options, Referrer-Policy, etc.) still only carry severity/status/recommendation, no stable ID field.

## Hardening still outstanding

- **No frontend tests** — backend has a full pytest suite (249 tests); the Next.js frontend has none (no jest/vitest configured).
- **No rate limiting** on `/api/scan` or `/api/explain` (the latter costs real money per call), or on login/register attempts (brute-force/account-creation throttling).
- **AI prompt-injection surface** — a malicious scanned site's own header values flow into the AI explanation prompt. Can't affect the PASS/FAIL verdict or score (already computed deterministically before the AI ever sees anything), but the explanation *text* itself isn't sanitized against injection attempts.
- No email verification or password-reset flow (needs real SMTP infra) — out of scope until this leaves localhost.
- No CI pipeline (lint/type-check/test-on-push).
- No DB migrations (Alembic) — every schema change so far (including the CSP overhaul) has required manually deleting the local `hedr.db` and letting it reseed. Fine at SQLite/hobby scale, not fine before any real deployment.
- No structured logging/observability beyond uvicorn's default access log.
- `npm audit` flags a moderate/high `postcss` advisory in Next's build tooling (dev-time only, not shipped to users) — fixing it means an unrequested Next.js major-version bump.

## Deployment

- **Not deployed anywhere** — runs locally only (`localhost:3000` frontend, `127.0.0.1:8123` backend). Recommendation when ready: Render (Vercel's serverless model doesn't fit the FastAPI + SQLite backend well).
