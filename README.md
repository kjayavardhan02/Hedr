# Hedr — HTTP Security Header Policy Analyzer

Hedr goes beyond "is this header present?" checks. You define a security
policy — what each header's value *should* be — and Hedr tells you exactly
what complies, what doesn't, why it matters, and how to fix it.

> **Traditional checker:** Is the header present?
> **Hedr:** Does the header comply with the policy you defined?

## Features

- **Scan by URL or raw response** — point Hedr at a live URL, or paste a
  response you captured yourself (Burp Suite, an internal/staging app, etc).
- **Custom policies** — define exactly what each header should look like,
  not just whether it exists. Built-in baselines (Basic, Strict, SaaS,
  Fintech) to start from and customize.
- **Deterministic rule engine** — exact-value, allowed-values (`a|b|c`),
  and directive-aware comparisons (e.g. HSTS `max-age` compared
  numerically, Permissions-Policy compared per-directive).
- **Dedicated CSP analyzer** — parses `Content-Security-Policy` into
  directives and checks both your policy's compliance *and* universal best
  practices (no wildcard sources, no `unsafe-inline`/`unsafe-eval`, missing
  `object-src`/`base-uri`/`frame-ancestors`) — always, regardless of policy.
- **Weighted security score** — 0-100 score and letter grade, computed
  entirely by deterministic rules.
- **AI-powered explanations** — for any failing/warning finding, get a
  plain-English explanation of what it does, why it matters, precise
  before/after fixes, and realistic tradeoffs. The AI never decides
  pass/fail — that verdict is 100% rule-based and already final before AI
  is ever called.
- **SSRF-guarded fetching** — scanning a URL blocks requests to
  private/internal/loopback addresses.

## Tech stack

| Layer    | Technology                                   |
|----------|-----------------------------------------------|
| Frontend | Next.js 15 (App Router) + TypeScript          |
| Backend  | Python + FastAPI + SQLite                     |
| AI       | Google Gemini (`google-genai` SDK)            |

## Project structure

```
Hedr/                    (repo root)
├── backend/             FastAPI app: policy engine, CSP analyzer, AI explainer
│   ├── app/
│   │   ├── core/         header parsing, SSRF-guarded fetcher, comparators,
│   │   │                 CSP analyzer, scoring, AI explainer
│   │   ├── routers/       /api/scan, /api/policies, /api/explain
│   │   └── baselines/     built-in policy templates (JSON)
│   └── requirements.txt
├── frontend/            Next.js app: scan UI, policy builder
│   └── src/
│       ├── app/           pages (scan, policies, policy editor)
│       ├── components/    UI components
│       └── lib/           API client + shared types
└── Hedr/
    └── Hedr_Idea.md      original product spec
```

## Getting started

### Prerequisites

- Python 3.10+
- Node.js 18+ and npm
- A Gemini API key (free tier works) for AI explanations — get one at
  [aistudio.google.com/apikey](https://aistudio.google.com/apikey). Optional:
  the rest of the app works fully without it.

### 1. Backend setup

```bash
cd backend
python3 -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# edit .env and set GEMINI_API_KEY (leave GEMINI_MODEL as-is unless you want a different model)
uvicorn app.main:app --reload --port 8123
```

The backend runs at `http://127.0.0.1:8123`. On first run it seeds the
built-in baseline policies into a local SQLite database (`backend/hedr.db`).

### 2. Frontend setup

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

The frontend runs at `http://localhost:3000` and automatically proxies
`/api/*` requests to the backend — no extra configuration needed for local
development.

### 3. Open the app

Visit **http://localhost:3000**.

## How to use it

### Scan a target

1. Go to the **Scan** page.
2. Choose **URL** or **Raw HTTP Response**.
   - *URL*: Hedr fetches the target server-side. Requests to private/internal
     addresses are blocked.
   - *Raw*: paste a response you already have — useful for staging/internal
     apps, or a response captured via a proxy like Burp Suite.
3. Pick a policy: a saved one, a built-in baseline, or build one ad-hoc for
   just this scan.
4. Click **Scan**. You get a score/grade, a pass/fail breakdown per header,
   and (if your policy includes CSP) a dedicated CSP analysis.
5. On any failing or warning finding, click **Explain with AI** for a
   breakdown: what the header/directive does, why the current config fails,
   precise before/after fixes, and tradeoffs of applying them.

### Create a policy

1. Go to **Policies → New Policy**.
2. For each header you want to enforce, add its name, the expected value,
   and whether it's required.
   - Leave the value blank to just require the header to be present.
   - Use `a|b|c` to accept multiple values, e.g. `no-referrer|strict-origin`.
   - `Strict-Transport-Security` and `Permissions-Policy` are compared
     directive-by-directive, e.g. `max-age=31536000; includeSubDomains; preload`.
   - `Content-Security-Policy` always gets the dedicated analyzer treatment —
     both your policy's directives and universal best practices are checked.
3. Save. Or start from a baseline (**Policies → Use as template**) and
   customize it instead of writing one from scratch.

## Running the backend tests

```bash
cd backend
source venv/bin/activate
pip install -r requirements-dev.txt
pytest                              # run the suite
pytest --cov=app --cov-report=term-missing   # with coverage
```

Tests point at a throwaway temp SQLite file (never `backend/hedr.db`) and
never make real network calls — URL fetches are mocked, so no live
API key or internet access is required to run them.

## Notes on the AI layer

- AI is called **on-demand only**, when you click "Explain with AI" on a
  specific finding — never automatically for every header on every scan.
- Without `GEMINI_API_KEY` set, everything else in Hedr still works; you'll
  just see an error if you click Explain.
- The deterministic rule engine decides every PASS/FAIL/WARNING verdict.
  AI only explains a verdict that's already been made — it cannot change it.

## Not yet included

- Scan history / security regression diffing over time
- CI/CD integration, policy-as-code
- Team accounts, multi-application monitoring, scheduled scans

See [`Hedr/Hedr_Idea.md`](Hedr/Hedr_Idea.md) for the full original product
spec and long-term roadmap.
