"use client";

import { useEffect, useRef, useState } from "react";
import { downloadReportPdf } from "@/lib/pdf";
import { downloadReportJson } from "@/lib/exportJson";
import type { ScanReport, ScanResult } from "@/lib/types";

export function ExportMenu({ data }: { data: ScanReport | ScanResult }) {
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
      >
        Export
        <span className={`chevron ${open ? "open" : ""}`}>▶</span>
      </button>

      {open && (
        <div className="export-menu-dropdown" role="menu">
          <button
            type="button"
            className="export-menu-item"
            role="menuitem"
            onClick={() => {
              downloadReportPdf(data);
              setOpen(false);
            }}
          >
            Download PDF
          </button>
          <button
            type="button"
            className="export-menu-item"
            role="menuitem"
            onClick={() => {
              downloadReportJson(data);
              setOpen(false);
            }}
          >
            Download JSON
          </button>
        </div>
      )}
    </div>
  );
}
