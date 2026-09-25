"use client";

import type { ReactNode } from "react";
import { DATE_PRESETS, presetRange } from "@/lib/filters";

export type FilterIconName = "target" | "policy" | "date" | "grade" | "search" | "type";

export function FilterIcon({ name }: { name: FilterIconName }) {
  const common = {
    width: 15,
    height: 15,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 2,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true,
  };
  switch (name) {
    case "target":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="9" />
          <circle cx="12" cy="12" r="4.5" />
          <circle cx="12" cy="12" r="1" />
        </svg>
      );
    case "policy":
      return (
        <svg {...common}>
          <path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z" />
        </svg>
      );
    case "date":
      return (
        <svg {...common}>
          <rect x="3.5" y="5" width="17" height="15" rx="2" />
          <path d="M3.5 10h17M8 3v4M16 3v4" />
        </svg>
      );
    case "grade":
      return (
        <svg {...common}>
          <path d="M12 3.5l2.6 5.3 5.9.9-4.3 4.1 1 5.8-5.2-2.8-5.2 2.8 1-5.8-4.3-4.1 5.9-.9L12 3.5z" />
        </svg>
      );
    case "type":
      return (
        <svg {...common}>
          <path d="M12 3l9 5-9 5-9-5 9-5z" />
          <path d="M3 13l9 5 9-5" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="11" cy="11" r="6.5" />
          <path d="M20 20l-4-4" />
        </svg>
      );
  }
}

export interface FilterTab<T extends string> {
  field: T;
  label: string;
  icon: FilterIconName;
}

/** Shared filter bar chrome: mode tabs, result summary, optional actions, and the active filter's controls. */
export function FilterBar<T extends string>({
  tabs,
  active,
  onTab,
  count,
  total,
  noun,
  pluralNoun,
  filterActive,
  onClear,
  actions,
  children,
}: {
  tabs: FilterTab<T>[];
  active: T;
  onTab: (field: T) => void;
  count: number;
  total: number;
  /** Singular noun for the summary pill, e.g. "report". */
  noun: string;
  /** Defaults to `noun` + "s"; pass for irregular plurals (policy -> policies). */
  pluralNoun?: string;
  filterActive: boolean;
  onClear: () => void;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="panel report-filter fade-in-up">
      <div className="rf-top">
        <div className="rf-tabs" role="tablist" aria-label="Filter by">
          {tabs.map((tab) => (
            <button
              key={tab.field}
              type="button"
              role="tab"
              aria-selected={active === tab.field}
              className={`rf-tab ${active === tab.field ? "rf-tab-active" : ""}`}
              onClick={() => {
                if (active !== tab.field) onTab(tab.field);
              }}
            >
              <FilterIcon name={tab.icon} />
              {tab.label}
            </button>
          ))}
        </div>
        <div className="rf-summary">
          <span className={`rf-count ${filterActive ? "rf-count-active" : ""}`}>
            {filterActive ? (
              <>
                <strong>{count}</strong> of {total} match
              </>
            ) : (
              <>
                <strong>{total}</strong> {total === 1 ? noun : (pluralNoun ?? `${noun}s`)}
              </>
            )}
          </span>
          {filterActive && (
            <button type="button" className="rf-clear" onClick={onClear}>
              Clear filter
            </button>
          )}
          {actions}
        </div>
      </div>
      <div className="rf-body">{children}</div>
    </div>
  );
}

export function SearchField({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder: string;
}) {
  return (
    <div className="rf-search">
      <FilterIcon name="search" />
      <input
        type="text"
        aria-label="Filter text"
        placeholder={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
      />
      {value && (
        <button type="button" className="rf-search-clear" aria-label="Clear search" onClick={() => onChange("")}>
          ×
        </button>
      )}
    </div>
  );
}

export function DateRangeFilter({
  from,
  to,
  onChange,
}: {
  from: string;
  to: string;
  onChange: (from: string, to: string) => void;
}) {
  return (
    <div className="rf-date">
      <div className="rf-chips">
        {DATE_PRESETS.map((preset) => {
          const range = presetRange(preset.days);
          const on = from === range.from && to === range.to;
          return (
            <button
              key={preset.label}
              type="button"
              className={`rf-chip ${on ? "rf-chip-on" : ""}`}
              aria-pressed={on}
              onClick={() => onChange(range.from, range.to)}
            >
              {preset.label}
            </button>
          );
        })}
      </div>
      <div className="rf-range">
        <label>
          <span>From</span>
          <input type="date" value={from} max={to || undefined} onChange={(e) => onChange(e.target.value, to)} />
        </label>
        <span className="rf-range-sep" aria-hidden="true">→</span>
        <label>
          <span>To</span>
          <input type="date" value={to} min={from || undefined} onChange={(e) => onChange(from, e.target.value)} />
        </label>
      </div>
    </div>
  );
}
