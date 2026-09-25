/** Live "n/max" counter for a limited input. `showFrom` (0-1) hides it until the
 * value is that full, for fields where an always-visible counter would be noise. */
export function CharCount({ length, max, showFrom = 0 }: { length: number; max: number; showFrom?: number }) {
  if (length < max * showFrom) return null;
  const state = length >= max ? "char-count-full" : length >= max * 0.9 ? "char-count-near" : "";
  return (
    <span className={`char-count ${state}`} aria-live="polite">
      {length.toLocaleString()}/{max.toLocaleString()}
    </span>
  );
}
