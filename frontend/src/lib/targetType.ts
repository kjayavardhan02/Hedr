/** What kind of target is being scanned - decides which headers apply.
 * Mirrors the backend's TargetType (schemas.py); the stored/API value is the
 * snake_case id, never the display label. */
export type TargetType = "web_application" | "rest_api" | "api_gateway" | "custom";

export const DEFAULT_TARGET_TYPE: TargetType = "web_application";

export const TARGET_TYPES: { id: TargetType; label: string; description: string }[] = [
  {
    id: "web_application",
    label: "Web Application",
    description: "Browser-facing sites and apps - every browser security header applies.",
  },
  {
    id: "rest_api",
    label: "REST API",
    description: "Endpoints consumed programmatically - browser-document headers (CSP, X-Frame-Options…) are N/A.",
  },
  {
    id: "api_gateway",
    label: "API Gateway",
    description: "A gateway-managed API surface - behaves like REST API for now.",
  },
  {
    id: "custom",
    label: "Custom",
    description: "You decide - every header in your policy is checked, nothing is skipped automatically.",
  },
];

/** One header that is N/A for a target type only under some condition. */
export interface ConditionalNotApplicable {
  header: string;
  when: string;
}

/** GET /api/scan/target-types - what each type is and which headers it marks N/A. */
export interface TargetTypeInfo {
  id: TargetType;
  label: string;
  description: string;
  always_not_applicable: string[];
  sometimes_not_applicable: ConditionalNotApplicable[];
}

/** Display label; a report saved before target types existed has none. */
export function targetTypeLabel(value: TargetType | null | undefined): string {
  return TARGET_TYPES.find((t) => t.id === value)?.label ?? "Not recorded";
}
