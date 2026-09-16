# Hedr --- AI-Based HTTP Security Header Policy Analyzer

## 1. Overview

**Hedr** is an AI-assisted HTTP Security Header Analyzer designed to go
beyond simple "header present/missing" checks.

The core idea is to allow users to:

1.  Provide a URL or paste an HTTP response/header set.
2.  Define a custom security header policy/template.
3.  Evaluate the actual HTTP response against that policy.
4.  Identify missing, incorrect, weak, or prohibited configurations.
5.  Use AI to explain findings and provide remediation recommendations.
6.  Give CSP special treatment because CSP requires deeper semantic
    analysis.

The initial focus is HTTP Security Headers, with the possibility of
expanding later into broader web security configuration.

------------------------------------------------------------------------

## 2. Problem

Most HTTP security header checkers primarily answer questions such as:

-   Is HSTS present?
-   Is CSP present?
-   Is X-Content-Type-Options present?
-   Is Referrer-Policy present?

However, **presence does not necessarily mean correct configuration**.

For example:

``` http
Strict-Transport-Security: max-age=100
```

The header exists, but a security team may require:

-   `max-age >= 31536000`
-   `includeSubDomains`
-   `preload`

A basic scanner may mark HSTS as present and pass it.

Hedr should instead answer:

> **Does this application's HTTP security configuration comply with the
> security policy I defined?**

------------------------------------------------------------------------

# 3. Core Concept: Policies Instead of Simple Templates

A basic template might look like:

``` text
Header: Strict-Transport-Security
Value: max-age=31536000; includeSubDomains; preload
```

Hedr should treat this as a **policy**.

A policy describes the expected security behavior rather than requiring
one exact string.

For example:

``` text
HSTS Policy

Header must exist

max-age:
    >= 31536000

includeSubDomains:
    required

preload:
    required
```

If the application returns:

``` http
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Hedr should report:

``` text
Header present              PASS
max-age >= 31536000         PASS
includeSubDomains           PASS
preload                     FAIL

Overall                     FAIL
```

This is the key distinction:

> **Traditional checker:** Is the header present?

> **Hedr:** Does the header comply with the expected security policy?

------------------------------------------------------------------------

# 4. Input Methods

Hedr should initially support two ways to provide data.

## 4.1 URL Input

The user provides:

``` text
https://example.com
```

Hedr fetches the HTTP response and analyzes the response headers.

Example flow:

``` text
URL
 ↓
HTTP Request
 ↓
HTTP Response
 ↓
Extract Headers
 ↓
Normalize Headers
 ↓
Policy Evaluation
 ↓
Findings
 ↓
AI Analysis
 ↓
Report
```

## 4.2 Raw HTTP Response / Headers

The user can paste something like:

``` http
HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
```

Hedr parses the response and performs the same analysis.

This is useful when:

-   The application is not publicly accessible.
-   The user is testing an internal/staging environment.
-   The user wants to analyze a response captured using Burp Suite or
    another proxy.
-   The user does not want Hedr to make the request itself.

------------------------------------------------------------------------

# 5. Policy Engine

The **Policy Engine** is the core of Hedr.

It compares:

``` text
User-defined Policy
        +
Actual HTTP Headers
        ↓
Policy Evaluation
        ↓
PASS / FAIL / WARNING
```

The policy engine should be deterministic and rule-based.

AI should not be responsible for deciding whether a rule passed or
failed.

------------------------------------------------------------------------

# 6. Types of Rules

Hedr can support different rule types.

## 6.1 Presence

Check whether a header exists.

Example:

``` text
Header:
X-Content-Type-Options

Required:
true
```

Result:

``` text
X-Content-Type-Options: Present
PASS
```

------------------------------------------------------------------------

## 6.2 Exact Value

Require an exact value.

Example:

``` text
X-Content-Type-Options

Expected:
nosniff
```

Actual:

``` http
X-Content-Type-Options: nosniff
```

Result:

``` text
PASS
```

------------------------------------------------------------------------

## 6.3 Allowed Values

Allow a defined set of values.

Example:

``` text
Referrer-Policy

Allowed:
- no-referrer
- strict-origin
- strict-origin-when-cross-origin
```

If the application returns:

``` http
Referrer-Policy: unsafe-url
```

Hedr reports:

``` text
FAIL

Value is not included in the organization's allowed values.
```

------------------------------------------------------------------------

## 6.4 Minimum Value

Useful for numeric directives.

Example:

``` text
Strict-Transport-Security

max-age >= 31536000
```

If the application returns:

``` http
Strict-Transport-Security: max-age=100
```

Result:

``` text
FAIL

Expected:
max-age >= 31536000

Actual:
max-age = 100
```

------------------------------------------------------------------------

## 6.5 Must Contain

Require a directive or value to exist.

Example:

``` text
Strict-Transport-Security

Must contain:
includeSubDomains
```

------------------------------------------------------------------------

## 6.6 Must Not Contain

Useful for security-sensitive directives.

Example:

``` text
Content-Security-Policy

script-src must NOT contain:
- unsafe-inline
- unsafe-eval
- *
```

------------------------------------------------------------------------

# 7. Example Policy

Internally, Hedr could represent a policy using JSON or YAML.

Example:

``` yaml
policy_name: Production Web Application

headers:

  strict-transport-security:
    required: true

    rules:
      max-age:
        operator: ">="
        value: 31536000

      includeSubDomains:
        required: true

      preload:
        required: true

  x-content-type-options:
    required: true
    expected_value: nosniff

  referrer-policy:
    required: true

    allowed_values:
      - no-referrer
      - strict-origin
      - strict-origin-when-cross-origin
```

The end user does not necessarily need to write YAML manually.

A UI can generate the policy.

------------------------------------------------------------------------

# 8. Policy Creation UI

The user could create a policy through a visual interface.

Example:

``` text
Create Security Policy

Policy Name:
[ Production Web Application ]

----------------------------------

Header:
[ Strict-Transport-Security ]

Required:
[ ✓ ]

Rules:

max-age
Operator: [ >= ]
Value:    [ 31536000 ]

includeSubDomains
[ ✓ Required ]

preload
[ ✓ Required ]

----------------------------------

[ Add Header ]

[ Save Policy ]
```

The UI converts these settings into the internal policy representation.

------------------------------------------------------------------------

# 9. Built-in Baselines

Hedr should provide predefined policies so users do not have to create
everything from scratch.

Possible baselines:

### Basic

A reasonable baseline for common web applications.

### Strict

A more security-focused configuration.

### SaaS Application

A baseline intended for SaaS web applications.

### Fintech

A stricter baseline appropriate for financial applications, subject to
appropriate review and customization.

### Custom

Users define their own policy.

The important point is that built-in baselines should be
**customizable**.

------------------------------------------------------------------------

# 10. CSP Should Have a Dedicated Analyzer

CSP should not be treated exactly like simple headers.

A basic header checker might only say:

``` text
Content-Security-Policy: Present
```

Hedr should analyze the actual CSP structure.

Example:

``` http
Content-Security-Policy:
default-src *;
script-src * 'unsafe-inline' 'unsafe-eval';
style-src * 'unsafe-inline';
```

The CSP analyzer should parse directives and evaluate security-relevant
characteristics.

Potential checks include:

``` text
CSP
 ├── default-src
 ├── script-src
 ├── style-src
 ├── connect-src
 ├── img-src
 ├── object-src
 ├── base-uri
 ├── frame-ancestors
 ├── form-action
 ├── worker-src
 ├── child-src
 ├── frame-src
 ├── wildcard sources
 ├── unsafe-inline
 ├── unsafe-eval
 ├── nonces
 ├── hashes
 └── dangerous or overly broad configurations
```

------------------------------------------------------------------------

# 11. CSP Policy Example

A user could define:

``` text
CSP Policy

Required:
yes

default-src:
required

script-src:
required

script-src must NOT contain:
- *
- unsafe-inline
- unsafe-eval

object-src:
must contain 'none'

base-uri:
must exist
```

Hedr then parses the actual CSP and evaluates each condition.

Example:

``` text
default-src exists          PASS
script-src exists           PASS
unsafe-inline prohibited    FAIL
unsafe-eval prohibited      PASS
wildcard prohibited         FAIL
object-src 'none'           FAIL
base-uri exists             FAIL
```

------------------------------------------------------------------------

# 12. AI Layer

AI should complement the deterministic rule engine.

The architecture should be:

``` text
HTTP Response
      ↓
Header Parser
      ↓
Policy Engine
      ↓
Deterministic Findings
      ↓
AI
      ↓
Explanation
      ↓
Recommendation
      ↓
Final Report
```

AI should **not** be the primary security verdict engine.

Instead, the rule engine determines the finding and AI explains it.

------------------------------------------------------------------------

# 13. AI Responsibilities

## 13.1 Explain Findings

Example finding:

``` text
CSP violates policy because script-src contains unsafe-inline.
```

AI can explain:

-   What the directive does.
-   Why it weakens CSP.
-   What security risk it introduces.
-   When it may be acceptable.
-   What impact removing it could have.

------------------------------------------------------------------------

## 13.2 Recommend Remediation

Example:

``` text
Current:
script-src 'self' 'unsafe-inline'
```

AI recommendation:

``` text
Consider replacing unsafe-inline with nonce- or hash-based
authorization for inline scripts where practical.
```

------------------------------------------------------------------------

## 13.3 Explain Tradeoffs

Security recommendations should not blindly say:

> "Remove this immediately."

For example, removing `unsafe-inline` can break an existing application.

AI can explain:

``` text
Potential impact:

Removing unsafe-inline may break existing inline scripts.
Test the updated CSP in Report-Only mode before enforcing it.
```

------------------------------------------------------------------------

## 13.4 Contextual Analysis

AI can provide additional context around a deterministic finding.

For example:

``` text
connect-src *
```

Instead of simply saying:

``` text
Wildcard detected.
```

AI could explain that the application may intentionally communicate with
multiple dynamic origins and that restricting the directive to known
origins would generally provide a tighter policy.

The AI should distinguish between:

``` text
Definitely violates user policy
```

and:

``` text
Potential security improvement
```

------------------------------------------------------------------------

# 14. Security Score

Hedr can provide a rule-based security posture score.

Example:

``` text
Security Header Score

72 / 100

HSTS                    20/20
CSP                     22/40
X-Content-Type-Options  10/10
Referrer-Policy           5/10
Permissions-Policy        5/10
COOP                      5/5
```

The score should be calculated by deterministic rules, not generated by
AI.

------------------------------------------------------------------------

# 15. Findings

Every finding should contain useful evidence.

Example:

``` text
Finding: HSTS-003

Severity:
Medium

Status:
FAIL

Policy:
max-age >= 31536000

Expected:
31536000 or greater

Actual:
max-age=100

Evidence:
Strict-Transport-Security: max-age=100

Recommendation:
Increase max-age according to the organization's security
baseline and deployment requirements.
```

This makes findings useful for security engineers and developers.

------------------------------------------------------------------------

# 16. Security Regression / Diff

A future feature should compare scans over time.

Example:

Previous CSP:

``` http
Content-Security-Policy:
default-src 'self';
script-src 'self' cdn.example.com;
```

New CSP:

``` http
Content-Security-Policy:
default-src *;
script-src * 'unsafe-inline';
```

Hedr could show:

``` diff
- default-src 'self'
+ default-src *

- script-src 'self' cdn.example.com
+ script-src * 'unsafe-inline'
```

And report:

``` text
Security regression detected.

Previous score:
91/100

Current score:
58/100
```

This can become especially valuable for continuous monitoring.

------------------------------------------------------------------------

# 17. Future: Continuous Monitoring

The initial product can be:

``` text
Enter URL
    ↓
Scan
    ↓
Report
```

A later SaaS version can become:

``` text
Add Application
       ↓
Scheduled Scans
       ↓
Policy Evaluation
       ↓
Configuration Change?
       ↓
Security Regression?
       ↓
Alert
```

Example:

``` text
Security Configuration Changed

api.example.com

CSP changed from:

script-src 'self' cdn.example.com

to:

script-src *
```

This moves Hedr from a one-time scanner toward continuous security
configuration monitoring.

------------------------------------------------------------------------

# 18. Future: Policy-as-Code

Eventually, organizations could manage policies as code.

Example:

``` yaml
policy:
  name: production-web

  hsts:
    required: true
    max_age:
      minimum: 31536000
    include_subdomains: true

  csp:
    required: true
    prohibited:
      - unsafe-inline
      - unsafe-eval
```

This could be stored in Git and integrated into CI/CD.

------------------------------------------------------------------------

# 19. Future CI/CD Integration

A later version could support:

``` text
Developer pushes code
        ↓
CI/CD Pipeline
        ↓
Deploy application
        ↓
Hedr Scan
        ↓
Evaluate policy
        ↓
PASS → Continue deployment
FAIL → Security gate / warning
```

Potential integrations could include:

-   GitHub
-   GitLab
-   CI/CD systems
-   Webhooks
-   Slack or other notification systems

------------------------------------------------------------------------

# 20. Potential Product Evolution

The initial scope should remain focused.

### V1 --- MVP

``` text
URL input
Raw header input
Header parser
Custom policies
Basic rule engine
Common security headers
Dedicated CSP analyzer
AI explanations
AI remediation recommendations
Security score
```

### V2

``` text
Multiple applications
Scheduled scans
Security regression detection
Historical results
Notifications
Team accounts
```

### V3

``` text
CI/CD integration
Policy-as-Code
Git integration
Security gates
API
```

### V4

Potentially expand beyond HTTP security headers into broader web
security configuration:

``` text
HTTP Security Headers
       ↓
CSP
       ↓
CORS
       ↓
Cookies
       ↓
TLS Configuration
       ↓
Cache Controls
       ↓
Other Web Security Configuration
```

------------------------------------------------------------------------

# 21. Recommended MVP Architecture

Keep the first version simple.

``` text
                 User
                   │
                   ↓
          ┌─────────────────┐
          │ URL / Raw Input │
          └────────┬────────┘
                   ↓
          ┌─────────────────┐
          │ Header Parser   │
          └────────┬────────┘
                   ↓
          ┌─────────────────┐
          │ Policy Engine   │
          └────────┬────────┘
                   ↓
          ┌─────────────────┐
          │ Findings Engine │
          └────────┬────────┘
                   ↓
          ┌────────┴────────┐
          ↓                 ↓
   Rule Evidence            AI
          │                 │
          └────────┬────────┘
                   ↓
               Report
```

The most important architectural principle is:

> **Deterministic engine for security decisions; AI for explanation and
> recommendations.**

------------------------------------------------------------------------

# 22. Product Positioning

Hedr should not be positioned only as:

> "An AI HTTP Security Header Checker."

That makes it sound like another online header scanning tool.

A stronger long-term positioning is:

> **Hedr --- Security Configuration Policy & Analysis for Web
> Applications.**

The core workflow becomes:

``` text
Define Policy
     ↓
Analyze Application
     ↓
Detect Violations
     ↓
Understand Findings
     ↓
Fix Issues
     ↓
Monitor for Regression
```

The core value proposition is:

> **Know what your application's security headers should look like,
> verify that they actually comply, and understand how to fix
> deviations.**

------------------------------------------------------------------------

# 23. Product Name

Working name:

## Hedr

The name can be changed later if a stronger brand is found.

For now, the working product identity is:

**Hedr**

Potential tagline:

> **Define. Check. Secure.**

Other possible directions:

> **Security headers, done right.**

> **Know what your headers should be.**

> **Turn security requirements into enforceable policies.**

------------------------------------------------------------------------

# 24. Guiding Principle

The product should start small.

Do not attempt to build a complete application security platform
immediately.

The first goal is:

``` text
HTTP Response
      ↓
Understand Headers
      ↓
Compare Against User Policy
      ↓
Find Violations
      ↓
Explain + Recommend
```

If this works well, the product can gradually evolve into a broader
**security configuration and policy monitoring platform**.
