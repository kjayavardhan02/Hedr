# Hedr — HTTP Security Header Policy Analyzer

## What is Hedr?

- A tool that checks the **security headers** a website or API sends back.
- You write a **policy** (the headers you want and the values you expect).
- Hedr scans a target and shows what **passes**, what **fails**, and **how to fix it**.

## What problem does it solve?

- Most header checkers only ask: *"is the header there?"*
- That misses the real question: **"does it match what we decided it should be?"**
- Hedr fixes this:
  - **Your rules** — every scan is judged against a policy you define.
  - **Clear results** — pass/fail is decided by rules, not AI. Spacing or ordering differences won't cause false failures.
  - **Fix guidance** — every failure says what's wrong and what to change.
  - **Fair scoring** — headers that don't apply (e.g. CSP on a JSON API) show as **N/A** and never lower your score.
  - **Progress tracking** — see what improved or got worse since the last scan.

## What can it do?

- **Scan three ways:**
  - A live **URL** — Hedr fetches it and reads the headers.
  - A pasted **raw HTTP response** — for sites you can't reach from the server.
  - A **Burp Suite history** import — check many endpoints at once.
- **Policies:**
  - Write your own, or start from built-in baselines (Basic, Strict, SaaS, Fintech).
  - Policies are versioned, and can be cloned.
- **Target types:** Web Application, REST API, API Gateway or Custom, so only relevant headers are checked.
- **Content-Security-Policy analysis:** checks your CSP against your policy and against common best practices.
- **Score and grade** for every scan (A–F), saved automatically as a report.
- **History:**
  - Compare a scan with the previous one for the same target.
  - Track the score over time.
- **Export** results as PDF, CSV, JSON, or Excel (Burp imports).
- **AI explanations (optional):** a plain-English "why it matters and how to fix it" for any failing header.
- **Two-factor sign-in (optional):** a one-time code sent to your email.
- **Private by default:** every policy and report belongs only to your account.

## How does it work?

- **1. You choose** a target, a **target type** and a **policy**.
- **2. Hedr gets the headers** — it fetches the URL from the server, or reads the response you pasted.
- **3. It decides what applies** — using the target type, HTTP vs HTTPS and the response's content type. Headers that don't apply become **N/A**.
- **4. It checks each header against your policy:**
  - Values are compared by meaning, so spacing, ordering or casing differences don't cause false failures.
  - CSP is analysed directive by directive.
  - This is all **fixed rules** — the same input always gives the same result.
- **5. It scores the scan** — only applicable checks count, so N/A never lowers the score.
- **6. It saves a report** and compares it with your previous scan of the same target.
- **7. AI is optional and only explains** — it never decides pass or fail.

## How to use it

### 1. Install and run

- You need **Python 3.10+** and **Node.js 18+**.
- **Backend:**
  ```bash
  cd backend
  python3 -m venv venv && source venv/bin/activate
  pip install -r requirements.txt
  cp .env.example .env
  uvicorn app.main:app --reload --port 8123
  ```
- Open `backend/.env` and set `JWT_SECRET_KEY`:
  - Generate one with `python -c "import secrets; print(secrets.token_hex(32))"`.
  - `GEMINI_API_KEY` is optional — only needed for "Explain with AI".
- **Frontend** (second terminal):
  ```bash
  cd frontend
  npm install
  npm run dev
  ```
- Open **http://localhost:3000**.

### 2. Create an account

- Go to **/signup**.
- Enter your name, email and a password (8+ characters).
- Click **Sign up**.

![Sign up page](docs/screenshots/01-signup.png)

### 3. Log in

- You're sent to the login page after signing up.
- Log in with the email and password you just chose.

![Log in page](docs/screenshots/02-login.png)

### 4. Start from the dashboard

- Your dashboard shows totals, your latest scan and recent scans.
- It's empty until your first scan.
- Click **+ New Scan**.

![Dashboard](docs/screenshots/03-dashboard.png)

### 5. Run your first scan

- On the **Scan** page, stay on the **URL** tab.
- **Target URL** — enter an address, e.g. `https://github.com`.
- **Target Type** — pick what you're scanning:
  - **Web Application** — a normal website opened in a browser.
  - **REST API** — an endpoint that returns data (JSON).
  - **API Gateway** — a gateway in front of several APIs.
  - **Custom** — nothing is skipped; every header in your policy is checked.
- Check the box under the dropdown — it lists which headers are **N/A** for that type.
- **Policy** — pick the rules to check against:
  - Four built-in baselines: **Basic**, **Strict**, **SaaS Application**, **Fintech**.
  - **Strict** is a good first choice.
- Click **Scan**.

![Scan form](docs/screenshots/04-scan-form.png)

- Private and internal addresses are blocked on purpose.
- For a site behind a VPN, use the **Raw HTTP Response** tab instead (see below).

### 6. Read the result

- At the top: your **score**, **grade**, and how many checks passed and failed.
- Below: one card per header:
  - **PASS** — matches the policy.
  - **FAIL** — missing or wrong. The card shows what was expected, what was sent, the problem, and the fix.
  - **N/A** — doesn't apply to this target. Shown with a reason and **not** counted in the score.
- **Explain with AI** gives a plain-English explanation (needs a Gemini key).
- **Export** downloads the result as PDF, CSV or JSON.

![Scan result](docs/screenshots/05-scan-result.png)

### 7. Find it again later

- Every scan is saved automatically.
- Open **Reports** in the sidebar to browse, filter and export them.

![Reports list](docs/screenshots/06-reports.png)

- Open a report to see:
  - Full findings.
  - A **score history** chart for that target.
  - **Changes since previous scan** — what improved or got worse.

![Single report](docs/screenshots/07-report.png)

## Other ways to scan

### Raw HTTP Response

- Use it when you already have a response (from `curl -i`, browser dev tools or a proxy), or the site isn't reachable from the server.
- Open the **Raw HTTP Response** tab, then:
  - Enter the **Target URL** it came from (used for matching only — never fetched).
  - Pick a **Target Type**.
  - Paste the response.
  - Click **Scan**.
- Click **Fill example** to see the expected format.

![Raw HTTP Response tab](docs/screenshots/10-raw-response.png)

### Burp History Import

- Use it to check many endpoints at once.
- Open the **Burp History Import** tab, then:
  - Drop in a Burp Suite HTTP-history export (XML).
  - Choose which hosts, methods and content types to include.
  - Pick a **Target Type** and a **Policy**.
  - Click **Analyze**.
- You get one report with per-header coverage, grouped findings and an Excel export.

![Burp History Import tab](docs/screenshots/11-burp-import.png)

## Policies

- A policy is the headers you want, the value you expect for each, and whether each is required.
- Open **Policies** in the sidebar.

![Policies page](docs/screenshots/08-policies.png)

- The four **baselines** are read-only — click **Use as template** to copy one.
- Click **+ New Policy** to write your own:
  - Add each header and its expected value.
  - Leave the value blank to only require the header to be present.
  - Separate several allowed values with `|`, e.g. `no-referrer|strict-origin`.
  - Tick **Required** if a missing header should fail.
  - Tick **Evaluate Content-Security-Policy** for detailed CSP rules.
- **Clone** a policy to make a variant.
- Editing a policy creates a new version — scans record which version they used.

![New Policy form](docs/screenshots/09-new-policy.png)

## Optional: two-factor sign-in

- Go to **Profile → Account Security → Enable MFA**.
- A 6-digit code is emailed to you; enter it to turn MFA on.
- After that, every login asks for your password, then a fresh emailed code (valid 5 minutes, one use).
- Turning MFA off needs your password **and** an emailed code.
- Requires email settings in `backend/.env`:
  ```
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_SECURITY=starttls
  SMTP_USERNAME=you@gmail.com
  SMTP_PASSWORD=your-app-password
  SMTP_FROM=Hedr Security <you@gmail.com>
  ```
- With Gmail, use an **app password**, not your normal password.
- Restart the backend after editing `.env`, and never commit `.env`.

![Account Security card](docs/screenshots/12-account-security.png)
