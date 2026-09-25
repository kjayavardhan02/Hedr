/** Header names that appear more than once in a policy (case-insensitive),
 * each listed once in the spelling first used. The backend rejects these on
 * save; checking here lets the builder warn before a round trip. */
export function duplicateHeaderNames(headers: { header_name: string }[]): string[] {
  const seen = new Map<string, string>();
  const duplicates: string[] = [];
  for (const { header_name } of headers) {
    const name = header_name.trim();
    if (!name) continue;
    const key = name.toLowerCase();
    const first = seen.get(key);
    if (first === undefined) seen.set(key, name);
    else if (!duplicates.includes(first)) duplicates.push(first);
  }
  return duplicates;
}

export function duplicateHeaderMessage(names: string[]): string {
  return `Each header can only appear once in a policy. Duplicate: ${names.join(", ")}.`;
}

const COPY_SUFFIX = /\s*\(copy(?: \d+)?\)$/i;

/** Name for a cloned policy: "X (copy)", then "X (copy 2)", "X (copy 3)" ...
 * whichever is not already taken. Cloning a copy reuses the original base
 * name instead of stacking suffixes, and the base is shortened if needed so
 * the result stays within the API's name length limit. */
export function uniqueCopyName(name: string, existingNames: string[], maxLength = 200): string {
  const base = name.replace(COPY_SUFFIX, "").trim() || name;
  const taken = new Set(existingNames.map((n) => n.trim().toLowerCase()));
  let candidate = "";
  for (let n = 1; n <= 1000; n++) {
    const suffix = n === 1 ? " (copy)" : ` (copy ${n})`;
    candidate = base.slice(0, Math.max(1, maxLength - suffix.length)).trimEnd() + suffix;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
  return candidate;
}
