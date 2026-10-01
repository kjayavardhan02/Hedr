import type { ReactNode } from "react";

/** A checkbox re-imagined as a toggleable pill, matching the same
 * clickable-chip language the Reports filter bar uses for its Grade filter -
 * a plain native checkbox would look like an afterthought next to the
 * rest of the app's styled controls. */
export function Chip({
  checked,
  onToggle,
  children,
  mono,
  disabled,
}: {
  checked: boolean;
  onToggle: () => void;
  children?: ReactNode;
  mono?: boolean;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="checkbox"
      aria-checked={checked}
      disabled={disabled}
      className={`burp-chip ${checked ? "burp-chip-on" : ""}`}
      onClick={onToggle}
    >
      <span className="burp-chip-check" aria-hidden="true">
        <svg viewBox="0 0 16 16" fill="none">
          <path d="M3.5 8.5 6.5 11.5 12.5 4.5" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </span>
      {children != null && <span className={mono ? "mono" : undefined}>{children}</span>}
    </button>
  );
}
