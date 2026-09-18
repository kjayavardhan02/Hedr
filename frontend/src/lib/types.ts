export type Status = "PASS" | "FAIL" | "WARNING" | "INFO";

export interface User {
  id: string;
  email: string;
  created_at: string;
}

export interface RegisterPayload {
  email: string;
  password: string;
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

export interface Policy {
  id: string;
  name: string;
  description: string;
  headers: PolicyHeader[];
  is_baseline: boolean;
  baseline_key: string | null;
  owner_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface PolicyCreatePayload {
  name: string;
  description: string;
  headers: PolicyHeader[];
}

export interface CheckResult {
  name: string;
  description: string;
  status: Status;
  expected: string | null;
  actual: string | null;
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

export interface ScanRequestPayload {
  source: "url" | "raw";
  url?: string;
  raw_response?: string;
  policy_id?: string;
  policy?: PolicyCreatePayload;
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
