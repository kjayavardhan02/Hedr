export type Theme = "dark" | "light" | "system";

const STORAGE_KEY = "hedr.theme";

function isTheme(value: string | null): value is Theme {
  return value === "dark" || value === "light" || value === "system";
}

/** Sets the `data-theme` attribute the CSS in globals.css keys off of, and
 * remembers the choice in localStorage so the next page load (before the
 * account's real preference is fetched) can guess correctly instead of
 * flashing dark by default every time. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage unavailable (private mode, blocked) - the page still themes
    // correctly for this load, it just won't be remembered for the next one.
  }
}

export function readStoredTheme(): Theme {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (isTheme(stored)) return stored;
  } catch {
    // ignore
  }
  return "dark";
}

/** Inlined into a blocking <script> in the document head (see layout.tsx) so
 * the right `data-theme` is set before first paint - without this, every
 * page load would flash dark (today's only theme) before React hydrates and
 * corrects it. Kept as one literal string, not a template built from
 * `STORAGE_KEY`, so its content is identical on every server render (the
 * inline script's text must match between server and client hydration). */
export const THEME_INIT_SCRIPT = `(function(){try{var t=localStorage.getItem("hedr.theme");document.documentElement.dataset.theme=(t==="light"||t==="system")?t:"dark";}catch(e){document.documentElement.dataset.theme="dark";}})();`;
