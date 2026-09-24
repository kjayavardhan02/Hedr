"use client";

import { useEffect, useState } from "react";
import {
  CACHE_CONTROL_FLAGS,
  ENUM_OPTIONS,
  headerKind,
  parseCacheControl,
  parseEnum,
  parseHsts,
  parseOrigin,
  parsePermissionsPolicy,
  parseXfo,
  parseXss,
  serializeCacheControl,
  serializeEnum,
  serializeHsts,
  serializeOrigin,
  serializePermissionsPolicy,
  serializeXfo,
  serializeXss,
  type AllowlistMode,
  type HeaderKind,
  type NumericOperator,
  type PermissionsFeatureRow,
} from "@/lib/headerValueSyntax";

const COMMON_PERMISSION_FEATURES = [
  "geolocation",
  "camera",
  "microphone",
  "fullscreen",
  "payment",
  "usb",
  "accelerometer",
  "gyroscope",
  "magnetometer",
  "autoplay",
  "display-capture",
  "clipboard-read",
  "clipboard-write",
  "midi",
];

interface EditorProps {
  value: string;
  onChange: (value: string) => void;
}

function digitsOnly(text: string): string {
  return text.replace(/\D/g, "");
}

function isRepresentable(kind: HeaderKind, headerName: string, value: string): boolean {
  switch (kind) {
    case "hsts":
      return parseHsts(value) !== null;
    case "cache-control":
      return parseCacheControl(value) !== null;
    case "origin":
      return parseOrigin(value) !== null;
    case "permissions-policy":
      return parsePermissionsPolicy(value) !== null;
    case "xss":
      return parseXss(value) !== null;
    case "xfo":
      return parseXfo(value) !== null;
    case "enum":
      return parseEnum(headerName, value) !== null;
  }
}

function HstsEditor({ value, onChange }: EditorProps) {
  const parsed = parseHsts(value);
  if (!parsed) return null;
  return (
    <div>
      <div className="hv-row">
        <label className="hv-label">max-age (seconds, at least)</label>
        <input
          className="hv-number"
          inputMode="numeric"
          placeholder="31536000"
          value={parsed.maxAge}
          onChange={(e) => onChange(serializeHsts({ ...parsed, maxAge: digitsOnly(e.target.value) }))}
        />
      </div>
      <div className="csp-directive-checks">
        <label className="csp-directive-check">
          <input
            type="checkbox"
            checked={parsed.includeSubDomains}
            onChange={(e) => onChange(serializeHsts({ ...parsed, includeSubDomains: e.target.checked }))}
          />
          <span>includeSubDomains required</span>
        </label>
        <label className="csp-directive-check">
          <input
            type="checkbox"
            checked={parsed.preload}
            onChange={(e) => onChange(serializeHsts({ ...parsed, preload: e.target.checked }))}
          />
          <span>preload required</span>
        </label>
      </div>
    </div>
  );
}

function CacheControlEditor({ value, onChange }: EditorProps) {
  const parsed = parseCacheControl(value);
  const [pendingOperator, setPendingOperator] = useState<NumericOperator>("=");
  if (!parsed) return null;

  const operator = parsed.maxAge?.operator ?? pendingOperator;

  function toggle(list: "required" | "prohibited", flag: string, checked: boolean) {
    const other = list === "required" ? "prohibited" : "required";
    const next = { ...parsed! };
    next[list] = checked ? [...next[list], flag] : next[list].filter((f) => f !== flag);
    if (checked) next[other] = next[other].filter((f) => f !== flag);
    onChange(serializeCacheControl(next));
  }

  return (
    <div>
      <div className="hv-group-label">Required directives</div>
      <div className="csp-directive-checks">
        {CACHE_CONTROL_FLAGS.map((flag) => (
          <label className="csp-directive-check" key={flag}>
            <input
              type="checkbox"
              checked={parsed.required.includes(flag)}
              onChange={(e) => toggle("required", flag, e.target.checked)}
            />
            <span className="mono">{flag}</span>
          </label>
        ))}
      </div>

      <div className="hv-row" style={{ marginTop: 10 }}>
        <label className="hv-label">max-age</label>
        <select
          className="hv-operator"
          value={operator}
          onChange={(e) => {
            const next = e.target.value as NumericOperator;
            setPendingOperator(next);
            if (parsed.maxAge) onChange(serializeCacheControl({ ...parsed, maxAge: { ...parsed.maxAge, operator: next } }));
          }}
        >
          <option value="=">equals</option>
          <option value=">=">at least</option>
          <option value="<=">at most</option>
        </select>
        <input
          className="hv-number"
          inputMode="numeric"
          placeholder="not checked"
          value={parsed.maxAge?.value ?? ""}
          onChange={(e) => {
            const digits = digitsOnly(e.target.value);
            onChange(
              serializeCacheControl({
                ...parsed,
                maxAge: digits ? { operator, value: digits } : null,
              })
            );
          }}
        />
      </div>

      <div className="hv-group-label" style={{ marginTop: 10 }}>
        Prohibited directives
      </div>
      <div className="csp-directive-checks">
        {CACHE_CONTROL_FLAGS.map((flag) => (
          <label className="csp-directive-check" key={flag}>
            <input
              type="checkbox"
              checked={parsed.prohibited.includes(flag)}
              onChange={(e) => toggle("prohibited", flag, e.target.checked)}
            />
            <span className="mono">{flag}</span>
          </label>
        ))}
      </div>

      <label className="csp-directive-check" style={{ marginTop: 10 }}>
        <input
          type="checkbox"
          checked={parsed.allowExtras}
          onChange={(e) => onChange(serializeCacheControl({ ...parsed, allowExtras: e.target.checked }))}
        />
        <span>Allow additional directives beyond these</span>
      </label>
    </div>
  );
}

function OriginEditor({ value, onChange }: EditorProps) {
  const parsed = parseOrigin(value);
  const [rows, setRows] = useState<string[]>(parsed?.origins ?? []);

  // Keep the local rows (which may include blank ones being typed) in step
  // with the stored value when it changes from outside this editor.
  useEffect(() => {
    const current = parseOrigin(value);
    if (current && serializeOrigin({ origins: rows, wildcard: current.wildcard }) !== value) {
      setRows(current.origins);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  if (!parsed) return null;

  function update(nextRows: string[], wildcard: boolean) {
    setRows(nextRows);
    onChange(serializeOrigin({ origins: nextRows, wildcard }));
  }

  return (
    <div>
      <div className="hv-group-label">Allowed origins</div>
      {rows.map((origin, i) => (
        <div className="hv-row" key={i}>
          <input
            className="hv-wide"
            placeholder="https://example.com"
            value={origin}
            onChange={(e) => update(rows.map((o, j) => (j === i ? e.target.value : o)), parsed.wildcard)}
          />
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => update(rows.filter((_, j) => j !== i), parsed.wildcard)}
          >
            Remove
          </button>
        </div>
      ))}
      <button type="button" className="btn btn-secondary btn-sm" onClick={() => setRows([...rows, ""])}>
        + Add origin
      </button>
      <label className="csp-directive-check" style={{ marginTop: 10 }}>
        <input
          type="checkbox"
          checked={parsed.wildcard}
          onChange={(e) => update(rows, e.target.checked)}
        />
        <span>Allow wildcard (*)</span>
      </label>
    </div>
  );
}

const ALLOWLIST_MODES: { value: AllowlistMode; label: string }[] = [
  { value: "none", label: "Disabled ()" },
  { value: "self", label: "Same origin (self)" },
  { value: "any", label: "Any origin (*)" },
  { value: "custom", label: "Custom list" },
];

function PermissionsPolicyEditor({ value, onChange }: EditorProps) {
  const parsed = parsePermissionsPolicy(value);
  const [rows, setRows] = useState<PermissionsFeatureRow[]>(parsed?.rows ?? []);

  useEffect(() => {
    const current = parsePermissionsPolicy(value);
    if (current && serializePermissionsPolicy({ rows }) !== value) {
      setRows(current.rows);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  if (!parsed) return null;

  function update(next: PermissionsFeatureRow[]) {
    setRows(next);
    onChange(serializePermissionsPolicy({ rows: next }));
  }

  function patch(index: number, change: Partial<PermissionsFeatureRow>) {
    update(rows.map((r, i) => (i === index ? { ...r, ...change } : r)));
  }

  return (
    <div>
      <datalist id="pp-features">
        {COMMON_PERMISSION_FEATURES.map((f) => (
          <option key={f} value={f} />
        ))}
      </datalist>
      {rows.map((row, i) => (
        <div className="hv-row" key={i}>
          <input
            className="hv-feature"
            list="pp-features"
            placeholder="feature, e.g. geolocation"
            value={row.feature}
            onChange={(e) => patch(i, { feature: e.target.value })}
          />
          <select value={row.mode} onChange={(e) => patch(i, { mode: e.target.value as AllowlistMode })}>
            {ALLOWLIST_MODES.map((m) => (
              <option key={m.value} value={m.value}>
                {m.label}
              </option>
            ))}
          </select>
          {row.mode === "custom" && (
            <input
              className="hv-wide"
              placeholder={'self "https://example.com"'}
              value={row.custom}
              onChange={(e) => patch(i, { custom: e.target.value })}
            />
          )}
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => update(rows.filter((_, j) => j !== i))}
          >
            Remove
          </button>
        </div>
      ))}
      <button
        type="button"
        className="btn btn-secondary btn-sm"
        onClick={() => setRows([...rows, { feature: "", mode: "none", custom: "" }])}
      >
        + Add feature
      </button>
    </div>
  );
}

function XssEditor({ value, onChange }: EditorProps) {
  const parsed = parseXss(value);
  if (!parsed) return null;
  return (
    <div className="hv-row">
      <select
        value={parsed.enabled}
        onChange={(e) =>
          onChange(serializeXss({ enabled: e.target.value as "" | "0" | "1", modeBlock: e.target.value === "1" && parsed.modeBlock }))
        }
      >
        <option value="">Presence only</option>
        <option value="0">0 — protection disabled</option>
        <option value="1">1 — protection enabled</option>
      </select>
      {parsed.enabled === "1" && (
        <label className="csp-directive-check">
          <input
            type="checkbox"
            checked={parsed.modeBlock}
            onChange={(e) => onChange(serializeXss({ ...parsed, modeBlock: e.target.checked }))}
          />
          <span className="mono">mode=block</span>
        </label>
      )}
    </div>
  );
}

function XFrameOptionsEditor({ value, onChange }: EditorProps) {
  const parsed = parseXfo(value);
  const [origins, setOrigins] = useState<string[]>(parsed?.allowFrom ?? []);

  // Keep local rows (which may include blank ones being typed) in step with
  // the stored value when it changes from outside this editor.
  useEffect(() => {
    const current = parseXfo(value);
    if (current && serializeXfo({ ...current, allowFrom: origins }) !== value) {
      setOrigins(current.allowFrom);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value]);

  if (!parsed) return null;

  function update(nextOrigins: string[], change: Partial<{ deny: boolean; sameorigin: boolean }> = {}) {
    setOrigins(nextOrigins);
    onChange(serializeXfo({ ...parsed!, ...change, allowFrom: nextOrigins }));
  }

  return (
    <div>
      <div className="csp-directive-checks">
        <label className="csp-directive-check">
          <input
            type="checkbox"
            checked={parsed.deny}
            onChange={(e) => update(origins, { deny: e.target.checked })}
          />
          <span className="mono">DENY</span>
        </label>
        <label className="csp-directive-check">
          <input
            type="checkbox"
            checked={parsed.sameorigin}
            onChange={(e) => update(origins, { sameorigin: e.target.checked })}
          />
          <span className="mono">SAMEORIGIN</span>
        </label>
      </div>

      <div className="hv-group-label" style={{ marginTop: 10 }}>
        <span className="mono">ALLOW-FROM</span> origins
      </div>
      {origins.map((origin, i) => (
        <div className="hv-row" key={i}>
          <input
            className="hv-wide"
            placeholder="https://example.com"
            value={origin}
            onChange={(e) => update(origins.map((o, j) => (j === i ? e.target.value : o)))}
          />
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={() => update(origins.filter((_, j) => j !== i))}
          >
            Remove
          </button>
        </div>
      ))}
      <button type="button" className="btn btn-secondary btn-sm" onClick={() => setOrigins([...origins, ""])}>
        + Add ALLOW-FROM origin
      </button>
      <span className="field-hint" style={{ display: "block", marginTop: 6 }}>
        Tick more than one option to accept any of them. ALLOW-FROM is obsolete: current browsers ignore
        it, so use CSP frame-ancestors for real protection.
      </span>
    </div>
  );
}

function EnumEditor({ headerName, value, onChange }: EditorProps & { headerName: string }) {
  const options = ENUM_OPTIONS[headerName.trim().toLowerCase()] ?? [];
  const selected = parseEnum(headerName, value);
  if (!selected) return null;
  return (
    <div>
      <div className="csp-directive-checks">
        {options.map((option) => (
          <label className="csp-directive-check" key={option}>
            <input
              type="checkbox"
              checked={selected.includes(option)}
              onChange={(e) =>
                onChange(
                  serializeEnum(
                    headerName,
                    e.target.checked ? [...selected, option] : selected.filter((s) => s !== option)
                  )
                )
              }
            />
            <span className="mono">{option}</span>
          </label>
        ))}
      </div>
      {options.length > 1 && (
        <span className="field-hint">Tick one for an exact match, or several to accept any of them.</span>
      )}
    </div>
  );
}

interface Props {
  headerName: string;
  value: string;
  onChange: (value: string) => void;
}

/** Structured editor for a header's expected value. Renders nothing for
 * headers with no dedicated syntax (the caller keeps its plain input). */
export function HeaderValueControls({ headerName, value, onChange }: Props) {
  const kind = headerKind(headerName);
  const [asText, setAsText] = useState(false);
  if (!kind) return null;

  const representable = isRepresentable(kind, headerName, value);
  const showText = asText || !representable;

  return (
    <div className="hv-controls">
      {showText ? (
        <>
          <input
            placeholder="Expected value (leave blank to just require presence)"
            value={value}
            onChange={(e) => onChange(e.target.value)}
          />
          {!representable && (
            <span className="field-hint">
              This value uses custom syntax the controls can&apos;t show, so it&apos;s edited as text.
            </span>
          )}
        </>
      ) : (
        <>
          {kind === "hsts" && <HstsEditor value={value} onChange={onChange} />}
          {kind === "cache-control" && <CacheControlEditor value={value} onChange={onChange} />}
          {kind === "origin" && <OriginEditor value={value} onChange={onChange} />}
          {kind === "permissions-policy" && <PermissionsPolicyEditor value={value} onChange={onChange} />}
          {kind === "xss" && <XssEditor value={value} onChange={onChange} />}
          {kind === "xfo" && <XFrameOptionsEditor value={value} onChange={onChange} />}
          {kind === "enum" && <EnumEditor headerName={headerName} value={value} onChange={onChange} />}
        </>
      )}
      {representable && (
        <button type="button" className="hv-toggle" onClick={() => setAsText(!asText)}>
          {asText ? "Use controls" : "Edit as text"}
        </button>
      )}
    </div>
  );
}
