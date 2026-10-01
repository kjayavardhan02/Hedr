import type { AccentColor } from "./accent";
import type { Theme } from "./theme";
import type { TargetType } from "./targetType";

export type Status = "PASS" | "FAIL" | "WARNING" | "INFO" | "NOT_APPLICABLE";

/** How a score's denominator was built: only applicable checks count, so
 * `applicable === passed + failed`; N/A checks are reported alongside. */
export interface ScoreBreakdown {
  applicable: number;
  passed: number;
  failed: number;
  not_applicable: number;
}

/** Every valid value for a user's stored theme preference. Re-exports
 * `Theme` (lib/theme.ts, the single source of truth) under the name these
 * API-facing types have always used. Mirrors the backend's `ThemeName`
 * (schemas.py). */
export type ThemePreference = Theme;

/** Re-exports `AccentColor` (lib/accent.ts) under the API-facing name.
 * Mirrors the backend's `AccentColor` (schemas.py). */
export type AccentPreference = AccentColor;

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  username: string | null;
  organization: string | null;
  job_title: string | null;
  /** The policy pre-selected on the Scan page, if one is set. */
  default_policy_id: string | null;
  /** Never null - the backend resolves an unset value to "dark". */
  theme: ThemePreference;
  /** Never null - the backend resolves an unset value to "default". */
  accent_color: AccentPreference;
  created_at: string;
}

/** GET /api/profile - a User plus the account-security fields no other
 * endpoint needs. */
export interface Profile extends User {
  /** Null until the password has ever been changed. */
  password_changed_at: string | null;
  /** Always false today - see Feature_Pending.md. */
  two_factor_enabled: boolean;
}

export interface ProfileUpdatePayload {
  first_name?: string;
  last_name?: string;
  /** "" clears it back to unset. */
  username?: string;
  organization?: string;
  job_title?: string;
}

export interface PasswordChangePayload {
  current_password: string;
  new_password: string;
}

export interface Preferences {
  default_policy_id: string | null;
  theme: ThemePreference;
  accent_color: AccentPreference;
}

/** PATCH body: every field optional and independent, same as ProfileUpdatePayload. */
export interface PreferencesUpdatePayload {
  default_policy_id?: string | null;
  theme?: ThemePreference;
  accent_color?: AccentPreference;
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
  /** CORS origin checks: the policy origin(s) after canonicalization, when it changed something. */
  normalized_expected?: string | null;
  /** CORS origin checks: plain-language reason for the verdict. */
  reason?: string | null;
}

export type SeverityLevel = "low" | "medium" | "high" | "critical" | "info";

/** A caveat separate from policy compliance (e.g. a header that passes its policy but is legacy). */
export interface Advisory {
  status: Status;
  severity: SeverityLevel;
  title: string;
  message: string;
  recommendation: string | null;
}

export interface HeaderFinding {
  header: string;
  required: boolean;
  present: boolean;
  status: Status;
  /** Null for a not-applicable header - it has no severity. */
  severity: "low" | "medium" | "high" | "critical" | "info" | null;
  weight: number;
  score_earned: number;
  score_possible: number;
  policy_expected: string | null;
  actual_value: string | null;
  checks: CheckResult[];
  /** What is wrong (only when the header did not pass; absent on older reports). */
  issue?: string | null;
  /** How to fix it. */
  recommendation: string | null;
  advisories?: Advisory[];
  /** False when skipped as not applicable (absent on reports saved before applicability existed = applicable). */
  applicable?: boolean;
  applicability_reason?: string | null;
}

export interface CSPFinding {
  present: boolean;
  actual_value: string | null;
  applicable?: boolean;
  applicability_reason?: string | null;
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
  /** Set only for a raw-response scan given a Target URL; null otherwise. */
  target_url?: string | null;
  fetched_status_code: number | null;
  policy_name: string;
  score: number;
  max_score: number;
  grade: string;
  findings: HeaderFinding[];
  csp_finding: CSPFinding | null;
  raw_headers: Record<string, string>;
  scanned_at: string;
  scanner_version?: string | null;
  target_type?: TargetType | null;
  breakdown?: ScoreBreakdown | null;
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
  target_url?: string | null;
  headers_evaluated: number;
  score: number;
  grade: string;
  scanned_at: string;
  /** Null for reports saved before target types existed ("Not recorded"). */
  target_type?: TargetType | null;
}

export interface ScanReport {
  id: string;
  scan_number: number;
  policy_id: string | null;
  policy_name: string;
  policy_version: string;
  source: "url" | "raw";
  target: string | null;
  target_url?: string | null;
  fetched_status_code: number | null;
  headers_evaluated: number;
  score: number;
  grade: string;
  findings: HeaderFinding[];
  csp_finding: CSPFinding | null;
  scanned_at: string;
  scanner_version?: string | null;
  target_type?: TargetType | null;
  breakdown?: ScoreBreakdown | null;
}

export interface ComparisonReportRef {
  id: string;
  scan_number: number;
  target: string | null;
  target_url?: string | null;
  target_type?: TargetType | null;
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

export interface ApplicabilityChange {
  header: string;
  previous_applicable: boolean;
  latest_applicable: boolean;
  previous_status: Status;
  latest_status: Status;
  reason: string | null;
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
  applicability_changes?: number;
}

export interface ComparisonChanges {
  headers_added: HeaderAdded[];
  headers_removed: HeaderRemoved[];
  headers_changed: HeaderChanged[];
  findings_resolved: FindingRef[];
  findings_new: FindingRef[];
  severity_changes: SeverityChange[];
  csp_changes: CSPChanges | null;
  applicability_changes?: ApplicabilityChange[];
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
  /** True when both scans recorded a target type and they differ. */
  target_type_changed?: boolean;
  changes: ComparisonChanges | null;
}

export interface TargetHistoryPoint {
  id: string;
  scan_number: number;
  score: number;
  grade: string;
  policy_name: string;
  policy_version: string;
  scanned_at: string;
}

export interface TargetHistoryResponse {
  has_history: boolean;
  reason: "ad_hoc_policy" | "anonymous_target" | "not_enough_data" | null;
  points: TargetHistoryPoint[];
}

export interface ScanRequestPayload {
  source: "url" | "raw";
  url?: string;
  raw_response?: string;
  target_name?: string;
  target_url?: string;
  target_type?: TargetType;
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
  target_url: string | null;
  score: number;
  grade: string;
  passed: number;
  failed: number;
  headers_evaluated: number;
  findings: DashboardFindings;
  scanned_at: string;
}

export interface DashboardBurpImport {
  id: string;
  name: string;
  policy_name: string | null;
  policy_version: string | null;
  target_type?: TargetType | null;
  score: number | null;
  responses_analyzed: number;
  imported_at: string;
  analyzed_at: string | null;
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
  recent_burp_imports: DashboardBurpImport[];
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

// ---------------------------------------------------------------------------
// Burp History Import - a third analysis source alongside URL/raw scans.
// Every entry is scored by the same policy engine; this is just the shape of
// the aggregate result across many responses. See backend app/schemas.py's
// "Burp History Import" section for the source of truth.
// ---------------------------------------------------------------------------

export interface BurpImportFacets {
  hosts: string[];
  methods: string[];
  status_buckets: string[];
  content_types: string[];
}

export interface BurpImportSummary {
  id: string;
  name: string;
  source_filename: string;
  entries_found: number;
  parsed_count: number;
  partial_count: number;
  failed_count: number;
  skipped_count: number;
  facets: BurpImportFacets;
  imported_at: string;
}

export interface BurpFiltersPayload {
  hosts?: string[] | null;
  methods?: string[] | null;
  status_buckets?: string[] | null;
  content_types?: string[] | null;
  https_only?: boolean;
  exclude_static?: boolean;
  deduplicate?: boolean;
}

export interface BurpAnalyzeRequestPayload {
  policy_id: string;
  filters?: BurpFiltersPayload;
  name?: string;
  target_type?: TargetType;
}

export type HeaderCoverageStatus = "present" | "missing" | "invalid" | "not_applicable";

export interface BurpHeaderResult {
  header: string;
  status: HeaderCoverageStatus;
  /** Why the header was skipped; set only when status is "not_applicable". */
  applicability_reason?: string | null;
  actual_value: string | null;
  expected_value: string | null;
  severity: SeverityLevel | null;
}

export interface BurpEndpointAnalysis {
  domain: string;
  path: string;
  raw_url: string;
  method: string;
  status_code: number | null;
  content_type: string | null;
  header_results: BurpHeaderResult[];
  policy_score: number;
  has_findings: boolean;
}

export interface BurpHostSummaryRow {
  host: string;
  responses: number;
  unique_paths: number;
  score: number;
}

export interface BurpHeaderCoverageRow {
  header: string;
  present: number;
  missing: number;
  invalid: number;
  not_applicable: number;
  coverage: number;
}

export interface BurpFindingGroup {
  header: string;
  status: "missing" | "invalid";
  severity: SeverityLevel;
  affected_count: number;
  affected_endpoints: string[];
}

export interface BurpInconsistencyConfig {
  value: string;
  count: number;
  affected_endpoints: string[];
}

export interface BurpHeaderInconsistency {
  header: string;
  configurations: BurpInconsistencyConfig[];
}

export interface BurpImportIssue {
  index: number;
  url: string | null;
  host: string | null;
  path: string | null;
  status: "parsed" | "partial" | "failed" | "skipped";
  reason: string | null;
}

export interface BurpAnalysisSummary {
  responses_analyzed: number;
  unique_hosts: number;
  unique_paths: number;
  overall_score: number;
  responses_with_findings: number;
  severity_counts: Record<string, number>;
  /** Header checks across all responses, N/A kept out of applicable/passed/failed. */
  checks?: ScoreBreakdown | null;
}

export interface BurpAnalysisResult {
  target_type?: TargetType | null;
  summary: BurpAnalysisSummary;
  host_summary: BurpHostSummaryRow[];
  header_coverage: BurpHeaderCoverageRow[];
  findings: BurpFindingGroup[];
  inconsistencies: BurpHeaderInconsistency[];
  endpoints: BurpEndpointAnalysis[];
  import_issues: BurpImportIssue[];
}

export interface BurpImportListItem {
  id: string;
  name: string;
  status: string;
  source_filename: string;
  policy_id: string | null;
  policy_name: string | null;
  policy_version: string | null;
  score: number | null;
  responses_analyzed: number;
  responses_skipped: number;
  parse_failures: number;
  imported_at: string;
  analyzed_at: string | null;
}

export interface BurpImportDetail {
  id: string;
  name: string;
  status: string;
  source_filename: string;
  policy_id: string | null;
  policy_name: string | null;
  policy_version: string | null;
  target_type?: TargetType | null;
  filters: BurpFiltersPayload | null;
  imported_at: string;
  analyzed_at: string | null;
  analysis: BurpAnalysisResult | null;
}


// --- Multi-factor authentication (email one-time codes) -----------------------

export interface MFAStatus {
  enabled: boolean;
  /** e.g. "j******@example.com" - never the full address. */
  masked_email: string;
  /** False when the server has no SMTP settings, so codes can't be sent. */
  email_configured: boolean;
}

/** A code was emailed. Times are in seconds. */
export interface MFACodeIssued {
  masked_email: string;
  expires_in: number;
  resend_available_in: number;
}

/** What POST /api/auth/login returns instead of a user when MFA is on. NOT a
 * session - the code still has to be submitted. */
export interface MFALoginChallenge extends MFACodeIssued {
  mfa_required: true;
  challenge_id: string;
}

export type LoginResult = User | MFALoginChallenge;

export function isMfaChallenge(result: LoginResult): result is MFALoginChallenge {
  return (result as MFALoginChallenge).mfa_required === true;
}
