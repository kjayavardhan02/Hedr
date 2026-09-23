# Hedr — Features Implemented

_Last updated: 2026-09-23_

Stack: Next.js 15 + TypeScript (frontend) · Python + FastAPI + SQLite (backend) · Gemini (AI explanations)

---

## Core scanning

- URL input scanning — server-side fetch, SSRF-guarded (blocks private/loopback/link-local/metadata addresses, closes DNS-rebinding gaps by connecting to the pre-validated IP directly).
- Raw HTTP response / headers paste input scanning, with an optional "Target name" field (defaults to `"HTTP Response Scan"`).
- Header parser: status line, CRLF normalization, obsolete line folding, duplicate headers joined with a comma.
- Deterministic rule engine: presence checks, exact-value match, allowed-values syntax (`a|b|c`), directive-aware comparators (HSTS `max-age`, Permissions-Policy allowlists).
- Weighted security score (0–100) + letter grade (A–F).
- Expanded header coverage: `Cache-Control`, `Access-Control-Allow-Origin`, `Access-Control-Allow-Credentials` (ACAC never flagged without ACAO present; policy builder suggests adding ACAO when ACAC is added).
- X-Frame-Options-via-CSP-`frame-ancestors` fallback: if XFO is missing but CSP's `frame-ancestors` provides equivalent protection, that's recognized instead of a false FAIL.

## Policies

- Custom policies: create/edit/delete, persisted in SQLite, scoped per-user.
- Built-in baselines (Basic, Strict, SaaS Application, Fintech) — read-only, clone-to-customize via "Use as template".
- Policy versioning: starts at `v1`, increments on every saved edit; baselines never change version. Each scan report snapshots the policy version at scan time. Ad-hoc (inline, never-saved) policies are labeled `"ad-hoc"`.

## Content-Security-Policy evaluation (full overhaul)

- Structured `csp_policy` on `Policy` — a dedicated field (`required`, `required_directives`, `directive_rules`), completely separate from the generic `headers` list. A policy can no longer express CSP as a free-text string; a schema validator rejects any attempt to put `Content-Security-Policy` back into `headers`.
- Per-directive rule types: required-directive presence, `must_contain`, `must_not_contain`, `allowed_sources` (allowlist), and 5 pattern-restriction toggles (`disallow_wildcards`/`external`/`http`/`data`/`blob`).
- Two independent evaluation layers, always both run:
  - **Policy compliance** — checked only against what you configured in `csp_policy`.
  - **Security best-practices** — always-on checks regardless of policy (wildcard sources, `unsafe-inline`, `unsafe-eval`, `data:`/`blob:` schemes on `script-src`/`style-src`, `object-src 'none'`, `base-uri`, `frame-ancestors`).
- Stable, centralized finding IDs (`CSP-000` through `CSP-014`) with per-finding-type severity (independent of the per-header severity table used elsewhere), plus `directive` and `evidence` fields on each check.
- CSP score breakdown: Policy Compliance (x/y), Best-Practice Checks (x/y), and an overall blended CSP score — all pooled into the scan's total score/grade.
- A CSP header PASS/FAIL badge, panel score breakdown, and any pass/fail tally always consider **both** layers combined — a bad CSP fails on best-practices even if the configured policy has no CSP rules at all.
- `CSPPolicyBuilder` (structured editor: required-directive checklist, repeatable directive-rule cards) and `CSPPolicySummary` (read-only rendering) components, wired into the ad-hoc scan builder and both policy create/edit pages.
- All 4 baselines carry a genuinely different CSP strictness profile (Basic minimal → Fintech strictest, with `form-action` locked down).
- Every UI surface that displays a policy's "size" now correctly reflects CSP-only policies instead of showing a misleading `0`/"no rules" (Reports popup, Dashboard "Your Policies" table + baseline cards, `/policies` list + baseline cards).

## Scan Reports (history)

- Every scan is automatically saved as a report — only the headers the policy actually evaluated (findings + CSP finding), never the full raw response.
- `/reports` list (compact card rows: scan number, target, policy + version, scanned date, headers evaluated, score badge) with view/delete; `/reports/[id]` detail view reuses the live-scan components.
- Per-user sequential scan numbering, collision-proof against deletions.
- Deleted-policy indicator: clicking a report's policy name opens a read-only preview popup if the policy still exists (now correctly shows CSP config, not just generic headers), or a toast if it's since been deleted.

## Dashboard

- `GET /api/dashboard/summary` — single endpoint backing the whole page: report/policy/baseline totals, average score across saved reports, latest scan, 5 most recent scans, findings-by-severity tally (now per-CSP-check severity, not a flat "any CSP failure = critical"), 4 most-recently-updated custom policies.
- Full overview page: greeting header, 4 metric cards, Latest Scan panel (score ring, pass-rate bar, headers evaluated, vs.-average delta), Recent Scans table, Findings-by-severity, Your Policies table (now flags CSP-only policies with a `CSP` badge instead of showing `0`), Security Baseline cards, Create Policy CTA.
- Real zero-states everywhere (no fake/demo data).

## Authentication

- Email/password accounts (bcrypt-hashed), open registration.
- JWT session in an `httpOnly` cookie, 1-hour expiry, `SameSite=Lax`.
- Every endpoint requires a valid session. Ownership enforced everywhere (policies/reports) — a 404, never a 403, on access to another user's resource.
- Generic login-failure message + dummy bcrypt check to prevent account enumeration / timing attacks.

## AI explanations

- On-demand, per-finding AI explanation (Gemini) via `/api/explain` — strictly explains an already-computed deterministic verdict, never re-judges PASS/FAIL/score.

## Export

- PDF export (client-side, `jspdf`): title, metadata, score, findings table, recommendations, and a CSP table (now with ID + Severity columns and the score-breakdown line) when applicable. Correct multi-page pagination.
- JSON export: full report/result object as-is, for piping into another tool or CI.

## Visual / UX

- Sidebar navigation (replaces old top nav), mobile hamburger drawer.
- Branded two-column login/signup screens, password strength meter.
- Tinted-glass dashboard cards, richer gradient buttons, ambient background glow.

## Testing / quality

- 249 backend pytest tests (comparators, header parser, CSP analyzer, scoring, policy engine, SSRF guard, security/JWT units, full API coverage per router including ownership isolation) — all passing.
- Frontend: `tsc --noEmit` clean across the whole project.
- Manual browser smoke-testing (Chrome extension) of every new UI surface: CSP policy builder, scan result CSP panel, dashboard tallies, policy preview popups.
