/** localStorage key prefix for saved list filters (see usePersistedState). */
export const SAVED_FILTERS_PREFIX = "hedr.filters.";

/** Removes every saved filter (called on logout). */
export function clearSavedFilters(): void {
  try {
    for (const key of Object.keys(localStorage)) {
      if (key.startsWith(SAVED_FILTERS_PREFIX)) localStorage.removeItem(key);
    }
  } catch {
    // Storage unavailable - nothing was saved.
  }
}
