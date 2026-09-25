"use client";

import { Fragment, useEffect, useId, useMemo, useRef, useState } from "react";
import { COMMON_HEADERS } from "@/lib/commonHeaders";
import { HEADER_NAME_MAX_LENGTH } from "@/lib/limits";
import { useMenuPlacement } from "@/lib/useMenuPlacement";
import { Highlight } from "./Highlight";

const norm = (name: string) => name.trim().toLowerCase();

type Option = { name: string; description: string; custom: boolean };

/** Searchable header-name dropdown. Headers already used by other rows of the
 * policy are left out, so a header can't be picked twice; any other header name
 * can still be typed in as a custom one. */
export function HeaderNameSelect({
  value,
  onChange,
  takenNames,
}: {
  value: string;
  onChange: (name: string) => void;
  /** Header names used by the other rows. */
  takenNames: string[];
}) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);
  const listId = useId();
  const placement = useMenuPlacement(open, triggerRef);

  const taken = useMemo(() => new Set(takenNames.map(norm)), [takenNames]);
  const available = useMemo(() => COMMON_HEADERS.filter((h) => !taken.has(norm(h.name))), [taken]);
  const hiddenCount = COMMON_HEADERS.length - available.length;

  const q = query.trim();
  const matches = useMemo(
    () => (q ? available.filter((h) => `${h.name} ${h.description}`.toLowerCase().includes(q.toLowerCase())) : available),
    [available, q]
  );

  // A typed name that isn't already listed or used becomes a "custom header" choice.
  const isCsp = norm(q) === "content-security-policy";
  const exactExists = COMMON_HEADERS.some((h) => norm(h.name) === norm(q));
  const alreadyUsed = taken.has(norm(q));
  const customOffered = q !== "" && !exactExists && !alreadyUsed && !isCsp;

  const options: Option[] = useMemo(
    () => [
      ...matches.map((h) => ({ ...h, custom: false })),
      ...(customOffered ? [{ name: q, description: "Use as a custom header name", custom: true }] : []),
    ],
    [matches, customOffered, q]
  );

  const known = COMMON_HEADERS.find((h) => norm(h.name) === norm(value));

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
    setActive(0);
    setOpen(true);
  }

  function close(refocus = true) {
    setOpen(false);
    if (refocus) triggerRef.current?.focus({ preventScroll: true });
  }

  function choose(index: number) {
    const option = options[index];
    if (option) onChange(option.name);
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
        setActive((i) => Math.min(options.length - 1, i + 1));
        break;
      case "ArrowUp":
        e.preventDefault();
        setActive((i) => Math.max(0, i - 1));
        break;
      case "Enter":
        e.preventDefault();
        choose(active);
        break;
      case " ":
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
        className={`ps-trigger ps-trigger-compact ${open ? "ps-trigger-open" : ""}`}
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? listId : undefined}
        onClick={() => (open ? close(false) : openMenu())}
      >
        <span className="ps-trigger-text">
          {value.trim() ? (
            <>
              <span className="ps-name">{value}</span>
              {known && <span className="ps-meta">{known.description}</span>}
            </>
          ) : (
            <span className="ps-name ps-placeholder">Select or type a header…</span>
          )}
        </span>
        {value.trim() && !known && <span className="ps-badge ps-badge-custom">Custom</span>}
        <span className={`ps-chevron ${open ? "ps-chevron-open" : ""}`} aria-hidden="true">
          ▾
        </span>
      </button>

      {open && (
        <div className={`ps-menu ps-menu-wide ${placement.up ? "ps-menu-up" : ""}`} style={{ maxHeight: placement.maxHeight }}>
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
              aria-activedescendant={options.length ? `${listId}-${active}` : undefined}
              aria-label="Search or type a header name"
              placeholder="Search or type a header name…"
              value={query}
              maxLength={HEADER_NAME_MAX_LENGTH}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => {
                setQuery(e.target.value);
                setActive(0);
              }}
            />
            <span className="ps-count">
              {matches.length}/{COMMON_HEADERS.length}
            </span>
          </div>

          <ul className="ps-list" role="listbox" id={listId} aria-label="Headers">
            {options.length === 0 && (
              <li className="ps-empty">
                {isCsp
                  ? "Content-Security-Policy has its own section below."
                  : alreadyUsed
                    ? `“${q}” is already in this policy.`
                    : available.length === 0
                      ? "All common headers are already added. Type a custom header name."
                      : `No headers match “${q}”.`}
              </li>
            )}
            {options.map((o, i) => (
              <Fragment key={`${o.custom ? "custom" : "common"}-${o.name}`}>
                {i === 0 && !o.custom && <li role="presentation" className="ps-group">Common headers</li>}
                {o.custom && <li role="presentation" className="ps-group">Custom</li>}
                <li
                  id={`${listId}-${i}`}
                  role="option"
                  aria-selected={norm(o.name) === norm(value)}
                  className={`ps-option ${i === active ? "ps-option-active" : ""} ${norm(o.name) === norm(value) ? "ps-option-selected" : ""}`}
                  onMouseEnter={() => setActive(i)}
                  onClick={() => choose(i)}
                >
                  <span className="ps-option-main">
                    <span className="ps-name">{o.custom ? `Use “${o.name}”` : <Highlight text={o.name} query={q} />}</span>
                    <span className="ps-desc">{o.description}</span>
                  </span>
                  {o.custom && <span className="ps-badge ps-badge-custom">Custom</span>}
                  <span className="ps-check" aria-hidden="true">
                    {norm(o.name) === norm(value) ? "✓" : ""}
                  </span>
                </li>
              </Fragment>
            ))}
          </ul>
          {hiddenCount > 0 && (
            <div className="ps-footnote">
              {hiddenCount} header{hiddenCount === 1 ? "" : "s"} already in this policy {hiddenCount === 1 ? "is" : "are"} hidden
            </div>
          )}
        </div>
      )}
    </div>
  );
}
