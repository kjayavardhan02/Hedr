export type Status = "PASS" | "FAIL" | "WARNING" | "INFO";

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  created_at: string;
}

export interface RegisterPayload {
  email: string;
  password: string;
  first_name: string;
  last_name: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface PolicyHeader {
  header_name: string;
  expected_value: string;
  required: boolean;
}

// Content-Security-Policy is never a generic header - it's configured
// separately via a structured rule set instead of one expected-value
// string, since it's a collection of independently-addressable directives.
export interface CSPDirectiveRule {
  directive: string;
  must_contain: string[];
  must_not_contain: string[];
  // null = no allowlist enforced; any non-null list means every actual
  // source in this directive must be one of these.
  allowed_sources: string[] | null;
  disallow_wildcards: boolean;
  disallow_external: boolean;
  disallow_http: boolean;
  disallow_data: boolean;
  disallow_blob: boolean;
}

export interface CSPPolicy {
  required: boolean;
  required_directives: string[];
  directive_rules: CSPDirectiveRule[];
}

export interface Policy {
  id: string;
  name: string;
  description: string;
  headers: PolicyHeader[];
  csp_policy: CSPPolicy | null;
  is_baseline: boolean;
  baseline_key: string | null;
  owner_id: string | null;
  version: number;
  created_at: string;
  updated_at: string;
}

export interface PolicyCreatePayload {
  name: string;
  description: string;
  headers: PolicyHeader[];
  csp_policy: CSPPolicy | null;
}

export interface CheckResult {
  name: string;
  description: string;
  status: Status;
  expected: string | null;
  actual: string | null;
  // Populated only for CSP findings - a stable CSP-### id, never derived
  // from the description text, plus the finding's own severity/directive.
  id: string | null;
  severity: "low" | "medium" | "high" | "critical" | "info" | null;
  directive: string | null;
  evidence: string | null;
}

export interface HeaderFinding {
  header: string;
  required: boolean;
  present: boolean;
  status: Status;
  severity: "low" | "medium" | "high" | "critical" | "info";
  weight: number;
  score_earned: number;
  score_possible: number;
  policy_expected: string | null;
  actual_value: string | null;
  checks: CheckResult[];
  recommendation: string | null;
}

export interface CSPFinding {
  present: boolean;
  actual_value: string | null;
  policy_checks: CheckResult[];
  security_checks: CheckResult[];
  directives: Record<string, string[]>;
  policy_checks_passed: number;
  policy_checks_total: number;
  best_practice_passed: number;
  best_practice_total: number;
  overall_score: number;
}

export interface ScanResult {
  id: string;
  source: "url" | "raw";
  target: string | null;
  fetched_status_code: number | null;
  policy_name: string;
  score: number;
  max_score: number;
  grade: string;
  findings: HeaderFinding[];
  csp_finding: CSPFinding | null;
  raw_headers: Record<string, string>;
  scanned_at: string;
}

export interface ScanReportSummary {
  id: string;
  scan_number: number;
  policy_id: string | null;
  policy_name: string;
  policy_version: string;
  source: "url" | "raw";
  target: string | null;
  headers_evaluated: number;
  score: number;
  grade: string;
  scanned_at: string;
}

export interface ScanReport {
  id: string;
  scan_number: number;
  policy_id: string | null;
  policy_name: string;
  policy_version: string;
  source: "url" | "raw";
  target: string | null;
  fetched_status_code: number | null;
  headers_evaluated: number;
  score: number;
  grade: string;
  findings: HeaderFinding[];
  csp_finding: CSPFinding | null;
  scanned_at: string;
}

export interface ScanRequestPayload {
  source: "url" | "raw";
  url?: string;
  raw_response?: string;
  target_name?: string;
  policy_id?: string;
  policy?: PolicyCreatePayload;
}

export interface DashboardScan {
  id: string;
  scan_number: number;
  policy_id: string | null;
  policy_name: string;
  policy_version: string;
  source: "url" | "raw";
  target: string | null;
  score: number;
  grade: string;
  passed: number;
  failed: number;
  headers_evaluated: number;
  findings: DashboardFindings;
  scanned_at: string;
}

export interface DashboardRecentPolicy {
  id: string;
  name: string;
  version: number;
  header_count: number;
  has_csp_policy: boolean;
  created_at: string;
  updated_at: string;
}

export interface DashboardFindings {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface DashboardSummary {
  reports: { total: number };
  policies: { total: number };
  baselines: { total: number };
  average_score: number | null;
  average_grade: string | null;
  latest_scan: DashboardScan | null;
  recent_scans: DashboardScan[];
  findings: DashboardFindings;
  recent_policies: DashboardRecentPolicy[];
}

export interface ApiErrorBody {
  detail: string;
}

export interface ExplainRequestPayload {
  name: string;
  policy_expected: string | null;
  actual_value: string | null;
  checks: CheckResult[];
}

export interface RecommendationItem {
  check: string;
  fix: string;
}

export interface ExplainResponse {
  what_it_does: string;
  why_it_matters: string;
  recommendations: RecommendationItem[];
  tradeoffs: string;
}
