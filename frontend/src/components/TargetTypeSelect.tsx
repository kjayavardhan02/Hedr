"use client";

import { useEffect, useId, useRef, useState } from "react";
import { api } from "@/lib/api";
import { TARGET_TYPES, type TargetType, type TargetTypeInfo } from "@/lib/targetType";
import { useMenuPlacement } from "@/lib/useMenuPlacement";

// The catalog never changes while the app is open, so fetch it once.
let catalogPromise: Promise<TargetTypeInfo[]> | null = null;
function loadCatalog(): Promise<TargetTypeInfo[]> {
  if (!catalogPromise) {
    catalogPromise = api.targetTypes().catch((e) => {
      catalogPromise = null; // let a later render retry
      throw e;
    });
  }
  return catalogPromise;
}

/** Which headers the selected target type marks N/A - always, and only under
 * some condition - read from the same rules the scanner applies. */
function NotApplicableSummary({ info }: { info: TargetTypeInfo }) {
  const always = info.always_not_applicable;
  const sometimes = info.sometimes_not_applicable;
  return (
    <div className="na-summary" aria-live="polite">
      <div className="na-summary-title">
        Headers marked <span className="badge badge-NOT_APPLICABLE">N/A</span> for {info.label}
      </div>
      {always.length === 0 && sometimes.length === 0 ? (
        <p className="field-hint" style={{ margin: 0 }}>
          None - every header in your policy is checked.
        </p>
      ) : (
        <>
          <div className="na-summary-row">
            <span className="na-summary-label">Always</span>
            {always.length > 0 ? (
              <span className="na-summary-tags">
                {always.map((h) => (
                  <span className="endpoint-tag mono" key={h}>
                    {h}
                  </span>
                ))}
              </span>
            ) : (
              <span className="field-hint">No header is always N/A.</span>
            )}
          </div>
          {sometimes.length > 0 && (
            <div className="na-summary-row">
              <span className="na-summary-label">Only when</span>
              <ul className="na-summary-list">
                {sometimes.map((c) => (
                  <li key={c.header}>
                    <span className="mono">{c.header}</span> - {c.when}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
      {(always.length > 0 || sometimes.length > 0) && (
        <p className="field-hint" style={{ margin: "8px 0 0" }}>
          N/A headers are skipped: they never fail and don&apos;t count toward the score.
        </p>
      )}
    </div>
  );
}

/** The Target Type control shared by the URL, raw-response and Burp flows.
 * Styled like PolicySelect (same .ps-* trigger, menu and options) so the two
 * dropdowns on the Scan page match; each option explains what the type means
 * for header applicability. */
export function TargetTypeSelect({
  value,
  onChange,
  style,
}: {
  value: TargetType;
  onChange: (next: TargetType) => void;
  style?: React.CSSProperties;
}) {
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  const [catalog, setCatalog] = useState<TargetTypeInfo[] | null>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const id = useId();
  const listId = `${id}-list`;
  const selected = TARGET_TYPES.find((t) => t.id === value) ?? TARGET_TYPES[0];
  const placement = useMenuPlacement(open, triggerRef);

  useEffect(() => {
    let cancelled = false;
    loadCatalog()
      .then((c) => {
        if (!cancelled) setCatalog(c);
      })
      .catch(() => {
        // Non-fatal: the dropdown still works, just without the N/A summary.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  useEffect(() => {
    if (open) document.getElementById(`${listId}-${active}`)?.scrollIntoView({ block: "nearest" });
  }, [open, active, listId]);

  function openMenu() {
    setActive(Math.max(0, TARGET_TYPES.findIndex((t) => t.id === value)));
    setOpen(true);
  }

  function close(refocus = true) {
    setOpen(false);
    if (refocus) triggerRef.current?.focus({ preventScroll: true });
  }

  function choose(index: number) {
    const option = TARGET_TYPES[index];
    if (option) onChange(option.id);
    close();
  }

  function onKeyDown(e: React.KeyboardEvent) {
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
        setActive((i) => Math.min(TARGET_TYPES.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        break;
      case "Home":
        e.preventDefault();
        setActive(0);
        break;
      case "End":
        e.preventDefault();
        setActive(TARGET_TYPES.length - 1);
        break;
      case "Enter":
      case " ":
        e.preventDefault();
        choose(active);
        break;
      case "Tab":
        close(false);
        break;
    }
  }

  return (
    <div className="field" style={style}>
      <label htmlFor={`${id}-trigger`}>Target Type</label>
      <div className="ps-root" ref={rootRef} onKeyDown={onKeyDown}>
        <button
          id={`${id}-trigger`}
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
              <circle cx="12" cy="12" r="9" />
              <circle cx="12" cy="12" r="4" />
              <path d="M12 3v3M12 18v3M3 12h3M18 12h3" />
            </svg>
          </span>
          <span className="ps-trigger-text">
            <span className="ps-name">{selected.label}</span>
            <span className="ps-meta">{selected.description}</span>
          </span>
          <span className={`ps-chevron ${open ? "ps-chevron-open" : ""}`} aria-hidden="true">
            ▾
          </span>
        </button>

        {open && (
          <div className={`ps-menu ${placement.up ? "ps-menu-up" : ""}`} style={{ maxHeight: placement.maxHeight }}>
            <ul className="ps-list" role="listbox" id={listId} aria-label="Target types">
              {TARGET_TYPES.map((t, i) => (
                <li
                  key={t.id}
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={t.id === value}
                  className={`ps-option ${i === active ? "ps-option-active" : ""} ${t.id === value ? "ps-option-selected" : ""}`}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(i)}
                >
                  <span className="ps-option-main">
                    <span className="ps-name">{t.label}</span>
                    <span className="ps-meta">{t.description}</span>
                  </span>
                  <span className="ps-check" aria-hidden="true">
                    {t.id === value ? "✓" : ""}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      {catalog?.find((t) => t.id === value) && <NotApplicableSummary info={catalog.find((t) => t.id === value)!} />}
    </div>
  );
}
