"use client";

import { useId } from "react";
import { TARGET_TYPES, type TargetType } from "@/lib/targetType";

/** The Target Type control shared by the URL, raw-response and Burp flows. The
 * description under it explains what the selected type means for header
 * applicability. */
export function TargetTypeSelect({
  value,
  onChange,
  style,
}: {
  value: TargetType;
  onChange: (next: TargetType) => void;
  style?: React.CSSProperties;
}) {
  const id = useId();
  const selected = TARGET_TYPES.find((t) => t.id === value);
  return (
    <div className="field" style={style}>
      <label htmlFor={id}>Target Type</label>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value as TargetType)}>
        {TARGET_TYPES.map((t) => (
          <option key={t.id} value={t.id}>
            {t.label}
          </option>
        ))}
      </select>
      {selected && <span className="field-hint">{selected.description}</span>}
    </div>
  );
}
