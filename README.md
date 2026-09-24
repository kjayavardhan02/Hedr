# Hedr — HTTP Security Header Policy Analyzer

Most header checkers only ask *"is the header present?"* Hedr asks
**"does it match the policy you defined?"** — and tells you what passes,
what fails, and how to fix it.

## What it does

- **Scan** a live URL, or paste a raw HTTP response you already have.
- **Policies** — write your own or start from a built-in baseline (Basic, Strict, SaaS, Fintech).
- **Clear pass/fail** — decided by rules, not AI. Values are compared by meaning, so spacing or ordering differences don't cause false failures.
- **CSP analysis** — checks your Content-Security-Policy against your policy and against common best practices.
- **Score and grade** for every scan, saved as a report.
- **Changes since the previous scan** — see what improved or regressed for the same target.
- **AI explanations** (optional) — a plain-English "why it matters and how to fix it" for any failing finding. The AI never decides pass/fail.

## Tech stack

Next.js + TypeScript (frontend) · FastAPI + SQLite (backend) · Google Gemini (optional AI)

## Getting started

You need Python 3.10+ and Node.js 18+.

**Backend**

```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env      # then set JWT_SECRET_KEY (see below)
uvicorn app.main:app --reload --port 8123
```

**Frontend** (in a second terminal)

```bash
cd frontend
npm install
npm run dev
```

Open **http://localhost:3000**, sign up, and run your first scan.

## Configuration

Edit `backend/.env`:

- `JWT_SECRET_KEY` — required. Generate one with
  `python -c "import secrets; print(secrets.token_hex(32))"`.
- `GEMINI_API_KEY` — optional. Only needed for "Explain with AI"; everything else works without it.
- `COOKIE_SECURE` — keep `false` for local `http://localhost`; set `true` when served over HTTPS.

## Good to know

- URL scans are fetched by the **backend**, and private or internal addresses are blocked on purpose. For a site only reachable through a VPN or internal network, copy its headers and use **Raw HTTP Response** mode.
- Every policy and report is private to the account that created it.

## Tests

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

See [`Hedr/Hedr_Idea.md`](Hedr/Hedr_Idea.md) for the original product idea and roadmap.
