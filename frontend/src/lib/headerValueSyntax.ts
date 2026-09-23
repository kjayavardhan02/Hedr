/**
 * Read/write the per-header "expected value" mini-syntax the backend
 * comparators understand (see backend/app/core/comparators.py). The policy
 * still stores one plain string per header; these helpers let the builder
 * show structured controls for it and turn them back into that string.
 *
 * Every parse* returns null for a string it cannot represent exactly, so the
 * UI can fall back to free text instead of silently rewriting a value.
 * The backend stays the source of truth for how a value is evaluated.
 */

export type HeaderKind =
  | "hsts"
  | "cache-control"
  | "origin"
  | "permissions-policy"
  | "xss"
  | "enum";

export const ENUM_OPTIONS: Record<string, string[]> = {
  "x-content-type-options": ["nosniff"],
  "x-frame-options": ["DENY", "SAMEORIGIN"],
  "referrer-policy": [
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
  ],
  "cross-origin-opener-policy": ["same-origin", "same-origin-allow-popups", "unsafe-none"],
  "cross-origin-resource-policy": ["same-origin", "same-site", "cross-origin"],
  "cross-origin-embedder-policy": ["require-corp", "credentialless", "unsafe-none"],
  "access-control-allow-credentials": ["true"],
};

export function headerKind(headerName: string): HeaderKind | null {
  const name = headerName.trim().toLowerCase();
  if (name === "strict-transport-security") return "hsts";
  if (name === "cache-control") return "cache-control";
  if (name === "access-control-allow-origin") return "origin";
  if (name === "permissions-policy") return "permissions-policy";
  if (name === "x-xss-protection") return "xss";
  if (name in ENUM_OPTIONS) return "enum";
  return null;
}

function splitTopLevel(value: string, separator: string): string[] {
  const parts: string[] = [];
  let current = "";
  let inQuote = false;
  let depth = 0;
  for (const char of value) {
    if (char === '"') inQuote = !inQuote;
    else if (!inQuote) {
      if (char === "(") depth += 1;
      else if (char === ")") depth = Math.max(0, depth - 1);
      else if (char === separator && depth === 0) {
        parts.push(current);
        current = "";
        continue;
      }
    }
    current += char;
  }
  parts.push(current);
  return parts;
}

// --- Strict-Transport-Security ---------------------------------------------

export interface HstsValue {
  maxAge: string;
  includeSubDomains: boolean;
  preload: boolean;
}

export function parseHsts(value: string): HstsValue | null {
  const result: HstsValue = { maxAge: "", includeSubDomains: false, preload: false };
  for (const raw of value.split(";")) {
    const part = raw.trim();
    if (!part) continue;
    const lower = part.toLowerCase();
    if (lower === "includesubdomains") result.includeSubDomains = true;
    else if (lower === "preload") result.preload = true;
    else {
      const match = /^max-age\s*=\s*(\d+)$/i.exec(part);
      if (!match || result.maxAge) return null;
      result.maxAge = match[1];
    }
  }
  return result;
}

export function serializeHsts(v: HstsValue): string {
  const parts: string[] = [];
  if (v.maxAge.trim()) parts.push(`max-age=${v.maxAge.trim()}`);
  if (v.includeSubDomains) parts.push("includeSubDomains");
  if (v.preload) parts.push("preload");
  return parts.join("; ");
}

// --- Cache-Control ---------------------------------------------------------

export const CACHE_CONTROL_FLAGS = [
  "no-store",
  "no-cache",
  "private",
  "public",
  "must-revalidate",
  "proxy-revalidate",
  "no-transform",
  "immutable",
];

export type NumericOperator = "=" | ">=" | "<=";

export interface CacheControlValue {
  required: string[];
  prohibited: string[];
  maxAge: { operator: NumericOperator; value: string } | null;
  allowExtras: boolean;
}

export function parseCacheControl(value: string): CacheControlValue | null {
  const result: CacheControlValue = { required: [], prohibited: [], maxAge: null, allowExtras: false };
  for (const raw of splitTopLevel(value, ",")) {
    const token = raw.trim();
    if (!token) continue;
    if (token === "+") {
      result.allowExtras = true;
    } else if (token.startsWith("!")) {
      const name = token.slice(1).trim().toLowerCase();
      if (!CACHE_CONTROL_FLAGS.includes(name) || result.prohibited.includes(name)) return null;
      result.prohibited.push(name);
    } else {
      const numeric = /^max-age\s*(>=|<=|=)\s*(\d+)$/i.exec(token);
      if (numeric) {
        if (result.maxAge) return null;
        result.maxAge = { operator: numeric[1] as NumericOperator, value: numeric[2] };
      } else {
        const name = token.toLowerCase();
        if (!CACHE_CONTROL_FLAGS.includes(name) || result.required.includes(name)) return null;
        result.required.push(name);
      }
    }
  }
  if (result.required.some((n) => result.prohibited.includes(n))) return null;
  return result;
}

export function serializeCacheControl(v: CacheControlValue): string {
  const parts: string[] = [];
  for (const flag of CACHE_CONTROL_FLAGS) if (v.required.includes(flag)) parts.push(flag);
  if (v.maxAge && v.maxAge.value.trim()) parts.push(`max-age${v.maxAge.operator}${v.maxAge.value.trim()}`);
  for (const flag of CACHE_CONTROL_FLAGS) if (v.prohibited.includes(flag)) parts.push(`!${flag}`);
  if (v.allowExtras && parts.length > 0) parts.push("+");
  return parts.join(", ");
}

// --- Access-Control-Allow-Origin -------------------------------------------

export interface OriginValue {
  origins: string[];
  wildcard: boolean;
}

export function parseOrigin(value: string): OriginValue | null {
  const result: OriginValue = { origins: [], wildcard: false };
  for (const raw of value.split("|")) {
    const item = raw.trim();
    if (!item) continue;
    if (item === "*") result.wildcard = true;
    else result.origins.push(item);
  }
  return result;
}

export function serializeOrigin(v: OriginValue): string {
  const items = v.origins.map((o) => o.trim()).filter(Boolean);
  if (v.wildcard) items.push("*");
  return items.join("|");
}

// --- Permissions-Policy ----------------------------------------------------

export type AllowlistMode = "none" | "self" | "any" | "custom";

export interface PermissionsFeatureRow {
  feature: string;
  mode: AllowlistMode;
  custom: string;
}

export interface PermissionsPolicyValue {
  rows: PermissionsFeatureRow[];
}

export function parsePermissionsPolicy(value: string): PermissionsPolicyValue | null {
  const rows: PermissionsFeatureRow[] = [];
  for (const raw of splitTopLevel(value, ",")) {
    const item = raw.trim();
    if (!item) continue;
    const match = /^([a-zA-Z0-9-]+)\s*=\s*\(([^)]*)\)$/.exec(item);
    if (!match) return null;
    const feature = match[1].toLowerCase();
    if (rows.some((r) => r.feature === feature)) return null;
    const tokens = match[2].trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) rows.push({ feature, mode: "none", custom: "" });
    else if (tokens.length === 1 && tokens[0] === "self") rows.push({ feature, mode: "self", custom: "" });
    else if (tokens.length === 1 && tokens[0] === "*") rows.push({ feature, mode: "any", custom: "" });
    else rows.push({ feature, mode: "custom", custom: tokens.join(" ") });
  }
  return { rows };
}

export function serializePermissionsPolicy(v: PermissionsPolicyValue): string {
  return v.rows
    .filter((r) => r.feature.trim())
    .map((r) => {
      const feature = r.feature.trim().toLowerCase();
      if (r.mode === "none") return `${feature}=()`;
      if (r.mode === "self") return `${feature}=(self)`;
      if (r.mode === "any") return `${feature}=(*)`;
      return `${feature}=(${r.custom.trim().split(/\s+/).filter(Boolean).join(" ")})`;
    })
    .join(", ");
}

// --- X-XSS-Protection ------------------------------------------------------

export interface XssValue {
  enabled: "" | "0" | "1";
  modeBlock: boolean;
}

export function parseXss(value: string): XssValue | null {
  const text = value.trim();
  if (!text) return { enabled: "", modeBlock: false };
  const normalized = text.replace(/\s+/g, "").toLowerCase();
  if (normalized === "0") return { enabled: "0", modeBlock: false };
  if (normalized === "1") return { enabled: "1", modeBlock: false };
  if (normalized === "1;mode=block") return { enabled: "1", modeBlock: true };
  return null;
}

export function serializeXss(v: XssValue): string {
  if (v.enabled === "") return "";
  if (v.enabled === "0") return "0";
  return v.modeBlock ? "1; mode=block" : "1";
}

// --- Enum headers ----------------------------------------------------------

export function parseEnum(headerName: string, value: string): string[] | null {
  const options = ENUM_OPTIONS[headerName.trim().toLowerCase()];
  if (!options) return null;
  const selected: string[] = [];
  for (const raw of value.split("|")) {
    const item = raw.trim();
    if (!item) continue;
    const canonical = options.find((o) => o.toLowerCase() === item.toLowerCase());
    if (!canonical || selected.includes(canonical)) return null;
    selected.push(canonical);
  }
  return selected;
}

export function serializeEnum(headerName: string, selected: string[]): string {
  const options = ENUM_OPTIONS[headerName.trim().toLowerCase()] ?? [];
  return options.filter((o) => selected.includes(o)).join("|");
}
