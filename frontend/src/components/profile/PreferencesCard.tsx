"use client";

import { useEffect, useMemo, useState, type CSSProperties } from "react";
import { useToast } from "@/components/Toast";
import { useAuth } from "@/lib/auth-context";
import { ApiError, api } from "@/lib/api";
import { PolicySelect } from "@/components/PolicySelect";
import { ScoreRing } from "@/components/ScoreRing";
import type { Policy } from "@/lib/types";
import { ACCENT_COLORS, applyAccent, getAccentChoicesForTheme, type AccentColor } from "@/lib/accent";
import { applyTheme, THEMES, type Theme } from "@/lib/theme";
import {
  IconBolt,
  IconCheck,
  IconMoon,
  IconPage,
  IconSliders,
  IconSnowflake,
  IconStars,
  IconSun,
  IconTerminalWindow,
} from "./icons";

const THEME_ICONS: Record<Theme, () => React.JSX.Element> = {
  light: IconSun,
  offwhite: IconPage,
  dark: IconMoon,
  cyberpunk: IconBolt,
  terminal: IconTerminalWindow,
  midnight: IconStars,
  arctic: IconSnowflake,
};

function ruleSummary(policy: Policy): string {
  const n = policy.headers.length;
  return `${n} header rule${n === 1 ? "" : "s"}${policy.csp_policy ? " · CSP" : ""}`;
}

export function PreferencesCard({
  defaultPolicyId,
  style,
}: {
  defaultPolicyId: string | null;
  style?: CSSProperties;
}) {
  const toast = useToast();
  const { user, refreshUser } = useAuth();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [value, setValue] = useState(defaultPolicyId ?? "");
  const [saving, setSaving] = useState(false);
  const [theme, setTheme] = useState<Theme>(user?.theme ?? "dark");
  const [themeSaving, setThemeSaving] = useState(false);
  const [accent, setAccent] = useState<AccentColor>(user?.accent_color ?? "default");
  const [accentSaving, setAccentSaving] = useState(false);

  useEffect(() => {
    api.listPolicies().catch(() => []).then((data) => setPolicies(data ?? []));
  }, []);

  useEffect(() => {
    setValue(defaultPolicyId ?? "");
  }, [defaultPolicyId]);

  useEffect(() => {
    if (user) setTheme(user.theme);
  }, [user?.theme]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (user) setAccent(user.accent_color);
  }, [user?.accent_color]); // eslint-disable-line react-hooks/exhaustive-deps

  const selectedPolicy = useMemo(() => policies.find((p) => p.id === value), [policies, value]);

  async function handleChange(next: string) {
    setValue(next);
    setSaving(true);
    try {
      await api.updatePreferences({ default_policy_id: next || null });
      await refreshUser();
      toast.show("Preferences saved.", "success");
    } catch (e) {
      setValue(defaultPolicyId ?? "");
      toast.show(e instanceof ApiError ? e.message : "Couldn't save preferences.", "error");
    } finally {
      setSaving(false);
    }
  }

  async function handleThemeChange(next: Theme) {
    const previous = theme;
    setTheme(next);
    applyTheme(next); // instant feedback - don't wait on the network for the page to re-theme
    setThemeSaving(true);
    try {
      await api.updatePreferences({ theme: next });
      await refreshUser();
      toast.show("Preferences saved.", "success");
    } catch (e) {
      setTheme(previous);
      applyTheme(previous);
      toast.show(e instanceof ApiError ? e.message : "Couldn't save preferences.", "error");
    } finally {
      setThemeSaving(false);
    }
  }

  async function handleAccentChange(next: AccentColor) {
    const previous = accent;
    setAccent(next);
    applyAccent(next); // instant feedback, same pattern as handleThemeChange
    setAccentSaving(true);
    try {
      await api.updatePreferences({ accent_color: next });
      await refreshUser();
      toast.show("Preferences saved.", "success");
    } catch (e) {
      setAccent(previous);
      applyAccent(previous);
      toast.show(e instanceof ApiError ? e.message : "Couldn't save preferences.", "error");
    } finally {
      setAccentSaving(false);
    }
  }

  return (
    <div className="panel panel-raised fade-in-up" id="preferences" style={style}>
      <h3 className="section-title" style={{ marginTop: 0, marginBottom: 14 }}>
        <span className="section-icon">
          <IconSliders />
        </span>
        Preferences
      </h3>

      <div className="field">
        <label>Appearance</label>
        <div className="theme-grid" role="radiogroup" aria-label="Appearance">
          {THEMES.map((t) => {
            const Icon = THEME_ICONS[t.id];
            const active = theme === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={active}
                className={`theme-card ${active ? "theme-card-active" : ""}`}
                disabled={themeSaving}
                onClick={() => handleThemeChange(t.id)}
              >
                {active && (
                  <span className="theme-card-check" aria-label="Selected">
                    <IconCheck />
                  </span>
                )}
                <div className="theme-card-header">
                  <span className="theme-card-icon">
                    <Icon />
                  </span>
                  <span className="theme-card-name">{t.name}</span>
                </div>
                <p className="theme-card-desc">{t.description}</p>
                <div className="theme-card-preview" data-theme={t.id}>
                  <ScoreRing score={92} grade="A" size={40} showLabel={false} />
                  <div className="theme-card-preview-badges">
                    <span className="badge badge-PASS">✓ HSTS</span>
                    <span className="badge badge-FAIL">✕ CSP</span>
                  </div>
                  <span className="btn btn-sm theme-card-preview-btn">Scan</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      <div className="field" style={{ marginTop: 16 }}>
        <label>Accent Color</label>
        <div className="accent-row" role="radiogroup" aria-label="Accent Color">
          {getAccentChoicesForTheme(theme).map((id) => {
            const active = accent === id;
            const meta = id === "default" ? null : ACCENT_COLORS.find((c) => c.id === id);
            return (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={active}
                title={id === "default" ? "Default" : meta?.name}
                className={`accent-swatch-btn ${active ? "accent-swatch-btn-active" : ""}`}
                disabled={accentSaving}
                onClick={() => handleAccentChange(id)}
              >
                <span
                  className="accent-swatch"
                  {...(id === "default" ? { "data-theme": theme } : {})}
                  style={id === "default" ? { background: "var(--accent)" } : { background: meta?.swatch }}
                >
                  {active && <IconCheck />}
                </span>
                <span className="accent-swatch-label">{id === "default" ? "Default" : meta?.name}</span>
              </button>
            );
          })}
        </div>
        <span className="field-hint">A curated set of accents that fit the current theme.</span>
      </div>

      <div className="field" style={{ marginTop: 16 }}>
        <label>Default Policy</label>
        <PolicySelect policies={policies} value={value} onChange={handleChange} allowNone />
        <span className="field-hint">Pre-selected when you start a new scan.</span>

        {selectedPolicy && (
          <div className="profile-policy-preview">
            <span className="profile-row-icon">
              <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                <path
                  d="M12 3 5 5.8v5.4c0 5 3.2 8.8 7 10.8 3.8-2 7-5.8 7-10.8V5.8L12 3Z"
                  stroke="currentColor"
                  strokeWidth="1.6"
                  strokeLinejoin="round"
                />
              </svg>
            </span>
            <div style={{ minWidth: 0, flex: 1 }}>
              <div style={{ fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {selectedPolicy.name}
              </div>
              <div className="field-hint">
                {selectedPolicy.is_baseline ? "Baseline" : `v${selectedPolicy.version}`} · {ruleSummary(selectedPolicy)}
              </div>
            </div>
            <span className={`ps-badge ${selectedPolicy.is_baseline ? "ps-badge-baseline" : "ps-badge-custom"}`}>
              {selectedPolicy.is_baseline ? "Baseline" : "Custom"}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}
