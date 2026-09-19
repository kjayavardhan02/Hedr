/** Capitalizes just the first character, leaving the rest untouched so
 * names like "McDonald" or "O'Brien" aren't mangled. */
export function capitalize(value: string): string {
  if (!value) return value;
  return value.charAt(0).toUpperCase() + value.slice(1);
}
