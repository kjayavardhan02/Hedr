"use client";

import { Fragment, useEffect, useId, useMemo, useRef, useState } from "react";
import type { Policy } from "@/lib/types";
import { useMenuPlacement } from "@/lib/useMenuPlacement";
import { Highlight } from "./Highlight";

function PolicyBadge({ policy }: { policy: Policy }) {
  return policy.is_baseline ? (
    <span className="ps-badge ps-badge-baseline">Baseline</span>
  ) : (
    <span className="ps-badge ps-badge-custom">Custom</span>
  );
}

function ruleSummary(policy: Policy): string {
  const n = policy.headers.length;
  return `${n} header rule${n === 1 ? "" : "s"}${policy.csp_policy ? " · CSP" : ""}`;
}

/** Styled, searchable replacement for a native <select> of policies: grouped
 * options with a description, rule summary and a Custom/Baseline badge. Opens
 * upward when there is more room above, and never taller than the window. */
export function PolicySelect({
  policies,
  value,
  onChange,
}: {
  policies: Policy[];
  value: string;
  onChange: (id: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listId = useId();

  // Custom policies first, then baselines - the order shown in the list.
  const ordered = useMemo(
    () => [...policies.filter((p) => !p.is_baseline), ...policies.filter((p) => p.is_baseline)],
    [policies]
  );
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ordered;
    return ordered.filter((p) =>
      `${p.name} ${p.description} ${p.is_baseline ? "baseline" : "custom"}`.toLowerCase().includes(q)
    );
  }, [ordered, query]);
  const selected = policies.find((p) => p.id === value) ?? null;

  const placement = useMenuPlacement(open, triggerRef);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  useEffect(() => {
    if (open) searchRef.current?.focus({ preventScroll: true });
  }, [open]);

  useEffect(() => {
    if (open) document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [open, active, listId]);

  function openMenu() {
    setQuery("");
    setActive(Math.max(0, ordered.findIndex((p) => p.id === value)));
    setOpen(true);
  }

  function close(refocus = true) {
    setOpen(false);
    if (refocus) triggerRef.current?.focus({ preventScroll: true });
  }

  function choose(index: number) {
    const policy = filtered[index];
    if (policy) onChange(policy.id);
    close();
  }

  function onKeyDown(e: React.KeyboardEvent) {
    const inSearch = e.target === searchRef.current;
    if (!open) {
      if (["ArrowDown", "ArrowUp", "Enter", " "].includes(e.key)) {
        e.preventDefault();
        openMenu();
      }
      return;
    }
    switch (e.key) {
      case "Escape":
        e.preventDefault();
        close();
        break;
      case "ArrowDown":
        e.preventDefault();
        setActive((i) => Math.min(filtered.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        break;
      case "Home":
        if (!inSearch) {
          e.preventDefault();
          setActive(0);
        }
        break;
      case "End":
        if (!inSearch) {
          e.preventDefault();
          setActive(filtered.length - 1);
        }
        break;
      case "Enter":
        e.preventDefault();
        choose(active);
        break;
      case " ":
        // A space is text while searching; otherwise it selects like Enter.
        if (!inSearch) {
          e.preventDefault();
          choose(active);
        }
        break;
      case "Tab":
        close(false);
        break;
    }
  }

  return (
    <div className="ps-root" ref={rootRef} onKeyDown={onKeyDown}>
      <button
        ref={triggerRef}
        type="button"
        className={`ps-trigger ${open ? "ps-trigger-open" : ""}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        onClick={() => (open ? close(false) : openMenu())}
      >
        <span className="ps-icon" aria-hidden="true">
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z" />
          </svg>
        </span>
        <span className="ps-trigger-text">
          {selected ? (
            <>
              <span className="ps-name">{selected.name}</span>
              <span className="ps-meta">
                v{selected.version} · {ruleSummary(selected)}
              </span>
            </>
          ) : (
            <span className="ps-name ps-placeholder">Select a policy</span>
          )}
        </span>
        {selected && <PolicyBadge policy={selected} />}
        <span className={`ps-chevron ${open ? "ps-chevron-open" : ""}`} aria-hidden="true">
          ▾
        </span>
      </button>

      {open && (
        <div className={`ps-menu ${placement.up ? "ps-menu-up" : ""}`} style={{ maxHeight: placement.maxHeight }}>
          <div className="ps-search">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <circle cx="11" cy="11" r="6.5" />
              <path d="M20 20l-4-4" />
            </svg>
            <input
              ref={searchRef}
              type="text"
              role="combobox"
              aria-expanded="true"
              aria-controls={listId}
              aria-activedescendant={filtered.length ? `${listId}-${active}` : undefined}
              aria-label="Search policies"
              placeholder="Search policies…"
              value={query}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
            />
            <span className="ps-count">
              {filtered.length}/{ordered.length}
            </span>
          </div>

          <ul className="ps-list" role="listbox" id={listId} aria-label="Policies">
            {filtered.length === 0 && <li className="ps-empty">No policies match &ldquo;{query.trim()}&rdquo;.</li>}
            {filtered.map((p, i) => {
              const startsGroup = i === 0 || filtered[i - 1].is_baseline !== p.is_baseline;
              return (
                <Fragment key={p.id}>
                  {startsGroup && (
                    <li role="presentation" className="ps-group">
                      {p.is_baseline ? "Built-in baselines" : "Your policies"}
                    </li>
                  )}
                  <li
                    id={`${listId}-${i}`}
                    role="option"
                    aria-selected={p.id === value}
                    className={`ps-option ${i === active ? "ps-option-active" : ""} ${p.id === value ? "ps-option-selected" : ""}`}
                    onMouseEnter={() => setActive(i)}
                    onClick={() => choose(i)}
                  >
                    <span className="ps-option-main">
                      <span className="ps-name">
                        <Highlight text={p.name} query={query} />
                      </span>
                      <span className="ps-meta">
                        {p.is_baseline ? "" : `v${p.version} · `}
                        {ruleSummary(p)}
                      </span>
                      {p.description && (
                        <span className="ps-desc">
                          <Highlight text={p.description} query={query} />
                        </span>
                      )}
                    </span>
                    <PolicyBadge policy={p} />
                    <span className="ps-check" aria-hidden="true">
                      {p.id === value ? "✓" : ""}
                    </span>
                  </li>
                </Fragment>
              );
            })}
          </ul>
        </div>
      )}
    </div>
  );
}
