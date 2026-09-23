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
