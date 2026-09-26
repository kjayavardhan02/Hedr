import { type Dispatch, type SetStateAction, useEffect, useState } from "react";
import { useAuth } from "./auth-context";
import { SAVED_FILTERS_PREFIX } from "./savedFilters";

/**
 * useState that survives navigating away and back (and a page refresh): the value
 * is kept in localStorage per user and page until it is set back to its default,
 * which removes it. It is read after mount, so the server render and first client
 * render always agree.
 */
export function usePersistedState<T>(page: string, name: string, initial: T): [T, Dispatch<SetStateAction<T>>] {
  const { user } = useAuth();
  const key = user ? `${SAVED_FILTERS_PREFIX}${user.id}.${page}.${name}` : null;
  const [value, setValue] = useState<T>(initial);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!key) return;
    try {
      const raw = localStorage.getItem(key);
      if (raw !== null) setValue(JSON.parse(raw) as T);
    } catch {
      // Corrupt or unavailable storage - fall back to the default.
    }
    setLoaded(true);
  }, [key]);

  useEffect(() => {
    if (!key || !loaded) return;
    try {
      if (JSON.stringify(value) === JSON.stringify(initial)) localStorage.removeItem(key);
      else localStorage.setItem(key, JSON.stringify(value));
    } catch {
      // Storage full or blocked - the filter still works, it just won't persist.
    }
    // `initial` is a constant default for a given call site.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, loaded, value]);

  return [value, setValue];
}
