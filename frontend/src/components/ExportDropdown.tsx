"use client";

import { useEffect, useRef, useState } from "react";

export interface ExportItem {
  label: string;
  onSelect: () => void | Promise<void>;
}

/** Button + dropdown of download options. */
export function ExportDropdown({
  label = "Export",
  items,
  disabled = false,
  busy = false,
}: {
  label?: string;
  items: ExportItem[];
  disabled?: boolean;
  busy?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function onClickOutside(e: MouseEvent) {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", onClickOutside);
    return () => document.removeEventListener("mousedown", onClickOutside);
  }, [open]);

  return (
    <div className="export-menu" ref={rootRef}>
      <button
        type="button"
        className="btn btn-sm"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        disabled={disabled || busy}
      >
        {busy ? "Exporting…" : label}
        <span className={`chevron ${open ? "open" : ""}`}>▶</span>
      </button>

      {open && (
        <div className="export-menu-dropdown" role="menu">
          {items.map((item) => (
            <button
              key={item.label}
              type="button"
              className="export-menu-item"
              role="menuitem"
              onClick={() => {
                setOpen(false);
                void item.onSelect();
              }}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
