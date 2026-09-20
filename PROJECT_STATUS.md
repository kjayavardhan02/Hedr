# Hedr — Project Status

_Last updated: 2026-09-20_

Repo: https://github.com/kjayavardhan02/Hedr
Stack: Next.js 15 + TypeScript (frontend) · Python + FastAPI + SQLite (backend) · Gemini (AI explanations)

---

## ✅ Done — V1 core (per `Hedr/Hedr_Idea.md` section 20)

| Feature | Status |
|---|---|
| URL input scanning | ✅ |
| Raw HTTP response input scanning | ✅ |
| Header parser | ✅ |
| Custom policies (create/edit/delete, persisted in SQLite) | ✅ |
| Built-in baselines (Basic, Strict, SaaS, Fintech) — clone-to-customize | ✅ |
| Deterministic rule engine — presence, exact-value, allowed-values (`a\|b\|c`), directive-aware comparison (HSTS `max-age`, Permissions-Policy) | ✅ |
| Dedicated CSP analyzer — policy compliance + always-on best-practice checks | ✅ |
| Weighted security score + letter grade | ✅ |
| AI explanations & remediation recommendations (Gemini, on-demand per finding) | ✅ |
| SSRF-guarded URL fetching (blocks private/loopback/link-local addresses) | ✅ |

### Hardening pass (post-V1 review)

- Request size limits on scan/explain inputs
- URL fetcher streams responses instead of buffering full bodies
- Explicit timeout on the Gemini API call
- **DNS-rebinding gap in the SSRF guard closed** — `fetch_headers` now connects directly to the pre-validated IP (never lets the HTTP client re-resolve DNS), while still sending the original hostname as the `Host` header and TLS SNI so cert validation/virtual hosting work normally.

---

## ✅ Done — since V1 (major additions this project)

### Automated backend test suite

- **192 pytest tests, 96% statement coverage** on `backend/app` (`pytest --cov=app`)
- Covers: pure-logic unit tests (comparators, header parser, CSP analyzer, scoring, policy engine), SSRF-guard edge cases, security/JWT unit tests, and full API tests for every router (auth, policies, scan, reports, explain) including ownership-isolation and ownership-IDOR scenarios
- Tests run against a throwaway temp SQLite file — never touch the real `hedr.db`
- Run with: `cd backend && pip install -r requirements-dev.txt && pytest`
- **Not yet done:** no frontend tests, no CI wiring to run this suite automatically on push

### Authentication + per-user policy ownership

- Email/password accounts (bcrypt-hashed, first/last name required, capitalized consistently wherever displayed). Registration is open.
- Sessions are a JWT in an `httpOnly` cookie (`hedr_session`) — `SameSite=Lax`, `Secure` gated behind `COOKIE_SECURE`, **1-hour expiry** (tightened down from an initial 7 days). Stateless, no server-side session store.
- Endpoints: `POST /api/auth/{register,login,logout}`, `GET /api/auth/me`.
- Every endpoint across the app requires a valid session — no anonymous access anywhere.
- Ownership enforced everywhere a policy or report is touched (list/get/update/delete/use-in-scan): visible only if it's a shared baseline or you own it, otherwise a **404** (never a 403 — a request never confirms another user's resource exists).
- Login failures return one identical generic message regardless of whether the email exists, with a dummy bcrypt check run either way to avoid timing-based account enumeration.
- Verified live in a real browser with two separate accounts, not just in tests.

### Sidebar navigation, Dashboard, and app restructuring

- Left sidebar (profile avatar + name, Dashboard/Scan/Policies/Reports links) replaces the old top nav bar entirely.
- Mobile: sidebar collapses to a hamburger-triggered slide-in drawer with a backdrop, auto-closes on navigation, locks background scroll while open.
- Scan moved from `/` to `/scan`; `/` just redirects to `/dashboard`.

### Dashboard overview page

- `GET /api/dashboard/summary` — one endpoint (scoped to the authenticated user, same ownership rules as Reports/Policies) backing the whole page instead of several chatty calls: report/policy/baseline totals, the average score across all saved reports (mean of final scores), the latest scan, the 5 most recent scans, a findings-by-severity tally scoped to *all* saved reports, and the 4 most-recently-updated custom policies.
- `/dashboard` is now a real security overview per the attached feature spec: welcome header with a time-of-day greeting, four metric cards, a prominent Latest Scan panel (score, pass-rate bar, headers evaluated, grade-tinted ambient glow), a Recent Scans list, findings-by-severity, a table of the user's own policies (name, version, rule count, created/updated timestamps), built-in baseline cards with view/clone actions, and a create-policy call to action.
- Every empty state (no reports, no custom policies yet) shows a real zero state — never fake/demo data.

### Scan Reports (history) — closes the old "no scan history" gap

- Every scan is now automatically saved as a report — **but only the headers the policy actually evaluated** (findings + CSP finding), never the full raw response header dump, to keep the table small and avoid storing data nobody asked to track.
- New `/reports` section: compact-row list (scan number, target, policy + version, scanned date, headers evaluated, score badge) with view/delete; `/reports/[id]` detail view reuses the same score-ring/finding-card/CSP-panel components as a live scan.
- Per-user sequential scan numbering (`MAX+1` at creation, so deleting a report never causes a number collision).
- Endpoints: `GET /api/reports`, `GET /api/reports/{id}`, `DELETE /api/reports/{id}` — same ownership isolation as policies. A report-save failure never blocks the scan response itself.

### Policy versioning

- A policy starts at `v1` and increments on every saved edit (not diffed against content — every successful edit is a new version). Baselines stay at `v1` forever (can't be edited).
- Each scan report snapshots the policy's version **at scan time** — editing the policy later never retroactively changes an old report's recorded version.
- Ad-hoc (inline, never-saved) policies are labeled `"ad-hoc"` rather than a fake `"v1"`, since there's no real version history for something used once.

### Deleted-policy indicator on Reports

- Every report now stores the `policy_id` it was scanned with (null for ad-hoc policies) — a historical pointer only, never a foreign key, so deleting the policy later never touches old reports.
- In both the Reports list and a report's detail page, the policy name is clickable for any report that used a saved policy: it opens a read-only preview modal (name, version, description, header rules, with an "Edit policy" link) if the policy still exists, or shows a toast ("This policy no longer exists — it may have been deleted since this scan.") if it's since been deleted. Ad-hoc policy names stay plain, non-interactive text.

### Target naming for raw-response scans

- Optional "Target name" field shown only in Raw HTTP Response mode (there's no URL to label a pasted response with). Defaults to `"HTTP Response Scan"` when left blank; has no effect on URL-sourced scans.

### Expanded security header coverage

- Added `Cache-Control`, `Access-Control-Allow-Origin`, and `Access-Control-Allow-Credentials` to the recognized header list (scoring weights/severities + policy-builder autocomplete).
- `Access-Control-Allow-Credentials` is never flagged when `Access-Control-Allow-Origin` is absent from the response, since ACAC has no effect in the browser without it.
- The policy builder suggests adding ACAO when ACAC is added and ACAO isn't already present in the policy (inline banner, not a native browser popup), and never repeats the suggestion once satisfied.

### Export: PDF and JSON

- Single "Export" dropdown (styled with the same orange gradient as other primary buttons) on both the live scan result and the saved report detail page, offering **Download PDF** and **Download JSON**.
- PDF is generated client-side (`jspdf` + `jspdf-autotable`): title, metadata, score, a findings table, a recommendations section for failing checks, and a CSP compliance/best-practice table when applicable — with correct multi-page pagination for long reports.
- JSON export downloads the already-fetched report/result object as-is, for piping into another tool or CI.
- PDF generation logic verified via a standalone Node script (base case, 25-finding pagination stress test, CSP-only and findings-only edge cases); the actual download trigger verified live in the browser via a `URL.createObjectURL` spy confirming real non-trivial PDF/JSON blobs.

### Visual/UX redesign

- Ambient background glow, sticky/blurred nav → sidebar, richer button styling (3-stop gradient, neutral elevation shadow + glossy inset highlight, tuned down from an earlier version that had too strong an orange glow), hover/press polish across the app.
- Full branded two-column login/signup screens (gradient visual panel + glass-panel form), password show/hide toggle, live password-strength meter on signup.
- Reports list iterated from a wide multi-column table (caused awkward horizontal scrolling) to compact policy-card-style rows — no scrolling needed, still shows every field.

---

## ⏳ Not done — known gaps

### V2 (deferred, per earlier instruction — not started)

- Multiple applications / multi-target tracking
- Scheduled scans
- Security regression detection (diff scans over time) — scan history itself is now done (see Reports above), but automatic regression *detection/diffing* between scans is not
- Notifications (Slack/email on regression)
- Team accounts / multi-user

### Hardening still outstanding

- **No frontend tests** — backend has a full pytest suite; the Next.js frontend has none yet.
- **No rate limiting** on `/api/scan` or `/api/explain` (the latter costs real money per call), or on login/register attempts specifically (brute-force/account-creation throttling).
- **AI prompt-injection surface** — a malicious scanned site's own header values flow into the AI explanation prompt. Can't affect the PASS/FAIL verdict or score (already computed deterministically), but could theoretically try to influence the explanation *text*. Not sanitized.
- No email verification or password reset flow (needs real SMTP infra) — out of scope until this leaves localhost.
- No CI pipeline (lint/type-check/test-on-push).
- No DB migrations (Alembic) — fine at SQLite/hobby scale, but every schema change this project has made so far has required manually deleting the local `hedr.db` (it's gitignored/disposable) and letting it reseed.
- No structured logging/observability beyond uvicorn's default access log.
- `npm audit` flags a moderate/high `postcss` advisory in Next's build tooling (dev-time only, not shipped to users) — fixing it means an unrequested Next.js major-version bump.

### Product-spec items not implemented

- Finding IDs (spec's `HSTS-003`-style stable identifiers) — findings have severity/status/checks/recommendation but no stable ID field.

### Deployment

- **Not deployed anywhere** — runs locally only (`localhost:3000` frontend, `127.0.0.1:8123` backend). Recommendation when ready: Render (not Vercel — its serverless model doesn't fit the FastAPI + SQLite backend well).

---

## Current state

Both dev servers are running locally (`localhost:3000` / `127.0.0.1:8123`).

Up to date with `main`: the JWT expiry change, the deleted-policy indicator on Reports, the PDF/JSON export feature, and the new Dashboard overview page are all committed and pushed.
