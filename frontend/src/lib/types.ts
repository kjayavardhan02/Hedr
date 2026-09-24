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
  /** The scan this one was compared against when saved, if any. */
  previous_report_id: string | null;
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

export interface ComparisonReportRef {
  id: string;
  scan_number: number;
  target: string | null;
  score: number;
  grade: string;
  scanned_at: string;
}

export interface HeaderAdded {
  header: string;
  latest_value: string | null;
}

export interface HeaderRemoved {
  header: string;
  previous_value: string | null;
}

export interface HeaderChanged {
  header: string;
  previous_value: string | null;
  latest_value: string | null;
}

export interface FindingRef {
  header: string;
  severity: "low" | "medium" | "high" | "critical" | "info";
  previous_status: Status;
  latest_status: Status;
}

export interface SeverityChange {
  header: string;
  previous_severity: "low" | "medium" | "high" | "critical" | "info";
  latest_severity: "low" | "medium" | "high" | "critical" | "info";
}

export interface CSPCheckRef {
  id: string;
  directive: string | null;
  category: "policy" | "security";
  description: string;
  severity: "low" | "medium" | "high" | "critical" | "info" | null;
  previous_status: Status;
  latest_status: Status;
}

export interface CSPDirectiveChanged {
  directive: string;
  previous_value: string[] | null;
  latest_value: string[] | null;
}

export interface CSPChanges {
  resolved: CSPCheckRef[];
  new: CSPCheckRef[];
  severity_changed: CSPCheckRef[];
  directive_changes: CSPDirectiveChanged[];
  previous_policy_checks_passed: number;
  previous_policy_checks_total: number;
  latest_policy_checks_passed: number;
  latest_policy_checks_total: number;
  previous_best_practice_passed: number;
  previous_best_practice_total: number;
  latest_best_practice_passed: number;
  latest_best_practice_total: number;
  previous_overall_score: number;
  latest_overall_score: number;
}

export interface ComparisonSummary {
  previous_score: number;
  latest_score: number;
  score_delta: number;
  previous_grade: string;
  latest_grade: string;
  headers_added: number;
  headers_removed: number;
  headers_changed: number;
  findings_resolved: number;
  findings_new: number;
  severity_changes: number;
}

export interface ComparisonChanges {
  headers_added: HeaderAdded[];
  headers_removed: HeaderRemoved[];
  headers_changed: HeaderChanged[];
  findings_resolved: FindingRef[];
  findings_new: FindingRef[];
  severity_changes: SeverityChange[];
  csp_changes: CSPChanges | null;
}

export interface ComparisonResponse {
  has_comparison: boolean;
  reason:
    | "ad_hoc_policy"
    | "raw_default_target"
    | "different_policy"
    | "policy_version_changed"
    | "previous_report_unavailable"
    | "no_previous_scan"
    | null;
  previous_report: ComparisonReportRef | null;
  latest_report: ComparisonReportRef | null;
  summary: ComparisonSummary | null;
  changes: ComparisonChanges | null;
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
  // A plain message, or a list of validation errors from request-schema checks.
  detail: string | { msg?: string }[];
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
