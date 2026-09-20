# Hedr --- Dashboard Feature Specification

## 1. Purpose

The Hedr Dashboard is the authenticated user's home page. It should
provide a concise overview of security-analysis activity, available
policies, and the user's next actions.

The Dashboard should answer:

1.  What can I do next?
2.  What happened recently?
3.  What security configuration/resources do I currently have?

It should not duplicate the full Scan, Policies, or Reports pages.

Current Hedr capabilities relevant to the Dashboard include URL
scanning, raw HTTP-response scanning, custom policies, built-in
baselines, deterministic rule evaluation, CSP analysis, weighted
security scoring, AI explanations/remediation, persisted reports, policy
versioning, and PDF/JSON export.

------------------------------------------------------------------------

## 2. Recommended Dashboard Structure

``` text
Dashboard
├── Welcome / New Scan
├── Summary Metrics
│   ├── Total Reports
│   ├── Your Policies
│   ├── Security Baselines
│   └── Average Score
├── Latest Scan
├── Recent 5 Scans
│   └── View All → Reports
├── Findings Summary
├── Your Policies
│   └── View All → Policies
├── Security Baselines
└── Create Policy
```

------------------------------------------------------------------------

# 3. Welcome / New Scan

## Purpose

Give the user an immediate entry point to perform a new security
analysis.

Example:

``` text
Good afternoon, Jayavardhan 👋

Analyze your application's security configuration.

[ + New Scan ]
```

Use the authenticated user's first name when available.

`+ New Scan` should navigate to the existing `/scan` page. Do not
implement scanning directly inside the Dashboard.

------------------------------------------------------------------------

# 4. Summary Metrics

Display four compact metric cards:

1.  Total Reports
2.  Your Policies
3.  Security Baselines
4.  Average Score

All metrics must be scoped to the authenticated user where applicable.

------------------------------------------------------------------------

## 4.1 Total Reports

Show the number of saved scan reports belonging to the current user.

Example:

``` text
Total Reports
12
```

Clicking the card can navigate to `/reports`.

Empty state:

``` text
Total Reports
0

Run your first scan to create a report.
```

Do not show fake/demo numbers.

------------------------------------------------------------------------

## 4.2 Your Policies

Show the number of custom policies owned by the current user.

Do not incorrectly include shared/built-in baselines in this count.

Example:

``` text
Your Policies
4
```

Click → `/policies`.

Empty state:

``` text
Your Policies
0

Create your first custom policy.
```

------------------------------------------------------------------------

## 4.3 Security Baselines

Show the number of available built-in baselines.

Current baselines:

-   Basic
-   Strict
-   SaaS
-   Fintech

Example:

``` text
Security Baselines
4
```

Clicking the card can navigate to `/policies`.

------------------------------------------------------------------------

## 4.4 Average Score

Show the arithmetic mean of the final scan scores across the user's
saved reports.

Example:

``` text
Reports:
100
80
90
70

Average = 85
```

Important:

-   Average the final scan scores.
-   Do not average individual header scores.
-   Do not average letter grades.
-   Do not display `0` when there are no reports; use `—`.

Example:

``` text
Average Score
85
B
Based on saved reports
```

If there are no reports:

``` text
Average Score
—

Run a scan to calculate your average.
```

The metric should be understood as an average of the currently saved
reports. This becomes important if Hedr later introduces configurable
report-retention limits.

------------------------------------------------------------------------

# 5. Latest Scan

This should be one of the most prominent Dashboard components.

Purpose:

> Show the most recent saved scan and make it immediately actionable.

Example:

``` text
Latest Scan

┌──────────────────────────────────────────────┐
│                    92                        │
│                     A                        │
│                                              │
│ example.com                                  │
│ Production Web · v3                          │
│ 10 passed · 2 failed                         │
│ Scanned 2 hours ago                          │
│                                              │
│                         [ View Report ]       │
└──────────────────────────────────────────────┘
```

Show:

-   Score
-   Grade
-   Target
-   Policy name
-   Policy version
-   Passed count
-   Failed count
-   Scan time

For raw HTTP-response scans, use the saved target name, such as
`HTTP Response Scan` or the user's custom target name.

`View Report` should navigate to:

``` text
/reports/{report_id}
```

Empty state:

``` text
Latest Scan

No scans yet.

[ Start Your First Scan ]
```

------------------------------------------------------------------------

# 6. Recent 5 Scans

Show only the latest five saved reports.

Do not show the entire report history on the Dashboard.

Example:

``` text
Recent Scans                              View All →

Target              Policy              Score   Date
-----------------------------------------------------
example.com         Production Web       92 A    2h ago
api.example.com     API Security         81 B    1d ago
github.com          Strict              100 A    Sep 18
```

Each item should contain:

-   Target
-   Policy name
-   Policy version
-   Score
-   Grade
-   Date/time

Clicking an item opens its report:

``` text
/reports/{report_id}
```

`View All →` navigates to:

``` text
/reports
```

------------------------------------------------------------------------

# 7. Findings Summary

This is optional but useful.

Show a concise summary of findings across saved reports.

Example:

``` text
Findings Across Saved Reports

Critical     High     Medium     Low
   0           2          5        1
```

The scope must be explicit. Do not make it appear that these counts
refer only to the latest scan.

If implementing this adds significant backend complexity, postpone it
until after the core Dashboard is complete.

------------------------------------------------------------------------

# 8. Your Policies

Surface a small number of the user's custom policies.

Example:

``` text
Your Policies                              View All →

┌─────────────────────┐  ┌─────────────────────┐
│ Production Web      │  │ API Security        │
│ v3 · 12 rules       │  │ v2 · 8 rules        │
│ Updated 2 days ago  │  │ Updated Sep 18      │
└─────────────────────┘  └─────────────────────┘
```

Show recently updated policies rather than trying to display every
policy.

Provide:

``` text
View All →
```

which navigates to `/policies`.

------------------------------------------------------------------------

# 9. Security Baselines

Surface the existing built-in baselines:

``` text
Basic
Strict
SaaS
Fintech
```

Example:

``` text
Security Baselines

[ Basic ] [ Strict ] [ SaaS ] [ Fintech ]
```

Because baselines support clone-to-customize, cards can optionally
offer:

``` text
[ View ]
[ Clone ]
```

Do not duplicate the entire policy builder on the Dashboard.

------------------------------------------------------------------------

# 10. Create Policy Quick Action

Provide a clear action for creating a custom policy.

Example:

``` text
Create a custom security policy

Define the headers and rules your applications should satisfy.

[ + Create Policy ]
```

Navigate to the existing policy creation workflow rather than
implementing the full builder inside the Dashboard.

------------------------------------------------------------------------

# 11. Recommended Visual Hierarchy

Not all Dashboard components should have equal visual weight.

### Highest priority

-   New Scan
-   Latest Scan

### Medium priority

-   Summary metrics
-   Recent Scans

### Lower priority

-   Findings Summary
-   Your Policies
-   Security Baselines
-   Create Policy

The Dashboard should feel like a security overview, not a collection of
equally sized cards.

------------------------------------------------------------------------

# 12. Responsive Design

## Desktop

Recommended arrangement:

``` text
Welcome / New Scan

4 Summary Metrics

Latest Scan       Findings Summary

Recent Scans

Your Policies

Security Baselines

Create Policy
```

## Tablet

Use two-column layouts where practical.

## Mobile

Use one column:

``` text
Welcome
New Scan
Metrics
Latest Scan
Recent Scans
Findings Summary
Your Policies
Security Baselines
Create Policy
```

Avoid horizontal scrolling.

------------------------------------------------------------------------

# 13. Empty State

A new account may have:

``` text
0 reports
0 custom policies
4 baselines
```

The Dashboard should still feel useful.

Example:

``` text
Welcome to Hedr 👋

Start by analyzing a URL or HTTP response.

[ + New Scan ]

Reports
0

Policies
0

Baselines
4

Average Score
—

Latest Scan
No scans yet.

[ Start Your First Scan ]

Your Policies
You haven't created a custom policy yet.

[ Create Policy ]

Security Baselines
Basic · Strict · SaaS · Fintech
```

Never insert fake scan data.

------------------------------------------------------------------------

# 14. Data/API Requirements

The Dashboard needs:

## Reports

-   Total report count
-   Latest report
-   Latest five reports
-   Score
-   Grade
-   Target
-   Policy name
-   Policy version
-   Timestamp
-   Passed/failed counts

## Policies

-   Total custom policy count
-   Recent policies
-   Policy name
-   Version
-   Rule/header count
-   Updated timestamp

## Baselines

-   Available baseline count
-   Baseline names

## Average Score

Calculate from saved report scores.

## Findings Summary

Calculate from saved report findings if implemented.

A dedicated endpoint is recommended if multiple existing API calls would
make the Dashboard unnecessarily chatty:

``` text
GET /api/dashboard/summary
```

Example response:

``` json
{
  "reports": {
    "total": 12
  },
  "policies": {
    "total": 4
  },
  "baselines": {
    "total": 4
  },
  "average_score": 87.3,
  "latest_scan": {
    "id": 42,
    "target": "https://example.com",
    "policy_name": "Production Web",
    "policy_version": 3,
    "score": 92,
    "grade": "A",
    "passed": 10,
    "failed": 2,
    "scanned_at": "2026-09-20T10:30:00Z"
  },
  "recent_scans": [],
  "findings": {
    "critical": 0,
    "high": 2,
    "medium": 5,
    "low": 1
  },
  "recent_policies": []
}
```

Adapt this to the existing backend/API conventions instead of blindly
creating duplicate endpoints.

------------------------------------------------------------------------

# 15. Security Requirements

The Dashboard is authenticated.

All data must be scoped to the current authenticated user.

Requirements:

-   Never trust a `user_id` supplied by the frontend.
-   Derive the user from the existing authentication/session mechanism.
-   Apply the same ownership rules already used by Reports and Policies.
-   Never expose another user's report counts, targets, scores,
    findings, or policies.
-   Built-in baselines can remain available to authenticated users.
-   Do not weaken existing ownership/404 behavior.

------------------------------------------------------------------------

# 16. Do NOT Add Yet

Do not add UI for features that are not implemented.

### Do not add:

-   Security score trend graph
-   Regression indicators
-   Applications overview
-   Scheduled scans
-   Notifications
-   "Issues Fixed"
-   "Vulnerabilities Resolved"
-   Team metrics
-   Fake security posture ratings

Regression/diff detection, applications, scheduled scans, notifications,
and team functionality are future features and should only appear once
their underlying functionality exists.

------------------------------------------------------------------------

# 17. Future Dashboard Evolution

Once future features exist, the Dashboard can later include:

``` text
Applications
Scans This Month
Open Findings
Regressions
Scheduled Scans
Score Trend
Applications Needing Attention
Recent Regressions
Alerts
```

Do not implement these just to make the Dashboard look larger.

------------------------------------------------------------------------

# 18. Final Recommended V1 Dashboard

``` text
┌───────────────────────────────────────────────────────────┐
│ Good afternoon, Jayavardhan 👋                           │
│ Analyze your application's security configuration.        │
│                                      [ + New Scan ]       │
└───────────────────────────────────────────────────────────┘

┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Reports      │ │ Policies     │ │ Baselines    │ │ Avg. Score   │
│     12       │ │      4       │ │      4       │ │     87       │
└──────────────┘ └──────────────┘ └──────────────┘ └──────────────┘

Latest Scan

┌───────────────────────────────────────────────────────────┐
│                         92                                │
│                          A                                │
│ example.com                                               │
│ Production Web · v3                                      │
│ 10 passed · 2 failed                                     │
│ 2 hours ago                                               │
│                                      [ View Report ]       │
└───────────────────────────────────────────────────────────┘

Recent Scans                                      View All →
─────────────────────────────────────────────────────────────
example.com       Production Web · v3       92 A
api.example.com   API Security · v2         81 B
github.com        Strict · v1              100 A
...

Findings Across Saved Reports
─────────────────────────────────────────────────────────────
Critical       High       Medium       Low
   0             2           5           1

Your Policies                                      View All →
─────────────────────────────────────────────────────────────
Production Web · v3        API Security · v2

Security Baselines
─────────────────────────────────────────────────────────────
[ Basic ] [ Strict ] [ SaaS ] [ Fintech ]

Create a custom policy
[ + Create Policy ]
```

------------------------------------------------------------------------

# 19. Implementation Priority

Build in this order:

### Phase 1 --- Core

1.  Welcome / New Scan
2.  Total Reports
3.  Your Policies count
4.  Security Baselines count
5.  Average Score

### Phase 2 --- Reports

6.  Latest Scan
7.  Recent 5 Scans
8.  View All → Reports

### Phase 3 --- Policies

9.  Your Policies cards
10. View All → Policies
11. Create Policy action
12. Security Baseline cards

### Phase 4 --- Optional Analytics

13. Findings Summary

The Dashboard should remain focused and data-driven. The main principle
is:

> **Dashboard = what happened recently, what do I have configured, and
> what should I do next?**

It should not become a second Scan page, a second Policies page, or a
future-feature showcase.
