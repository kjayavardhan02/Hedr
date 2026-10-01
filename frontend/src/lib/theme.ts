import { ACCENT_INIT_SNIPPET, applyAccent, readStoredAccent } from "./accent";

// "system" (track the OS's light/dark preference) was removed - it never
// resolved to anything other than Light or Default, so it was redundant
// with Default (Hedr's own default appearance) once themes had names of
// their own. A legacy stored "system" value is coerced to "dark" both here
// (readStoredTheme/THEME_INIT_SCRIPT) and on the backend (schemas.py).
export type Theme = "dark" | "light" | "offwhite" | "cyberpunk" | "terminal" | "midnight" | "arctic";

const STORAGE_KEY = "hedr.theme";

/** Single source of truth for every valid stored value - `isTheme` and the
 * inline pre-hydration script below both derive from this, so the allowed
 * set can't drift out of sync as themes are added. */
const THEME_VALUES: readonly Theme[] = [
  "dark",
  "light",
  "offwhite",
  "cyberpunk",
  "terminal",
  "midnight",
  "arctic",
];

/** Metadata for every named theme, driving the theme-card picker in
 * PreferencesCard. Stable `id`s per the spec - never used as display text
 * directly. */
export const THEMES: { id: Theme; name: string; description: string }[] = [
  { id: "light", name: "Light", description: "Clean and bright, for daytime use." },
  { id: "offwhite", name: "Offwhite", description: "Soft neutral off-white with a sage accent." },
  { id: "dark", name: "Default", description: "Hedr's original, low-glare theme." },
  { id: "cyberpunk", name: "Cyberpunk", description: "Neon cyan on near-black." },
  { id: "terminal", name: "Terminal", description: "Security-terminal green on black." },
  { id: "midnight", name: "Midnight", description: "Deep navy with a cool purple accent." },
  { id: "arctic", name: "Arctic", description: "Cool white with a cyan accent." },
];

function isTheme(value: string | null): value is Theme {
  return value !== null && (THEME_VALUES as readonly string[]).includes(value);
}

/** Sets the `data-theme` attribute the CSS in globals.css keys off of, and
 * remembers the choice in localStorage so the next page load (before the
 * account's real preference is fetched) can guess correctly instead of
 * flashing dark by default every time. Also re-applies the stored accent
 * color, since a non-"default" accent's exact hex depends on whether the
 * *new* theme is light- or dark-family (see lib/accent.ts) - without this,
 * switching themes while a custom accent is active would leave the old
 * family's hex in place until the next full reload. */
export function applyTheme(theme: Theme): void {
  document.documentElement.dataset.theme = theme;
  try {
    localStorage.setItem(STORAGE_KEY, theme);
  } catch {
    // Storage unavailable (private mode, blocked) - the page still themes
    // correctly for this load, it just won't be remembered for the next one.
  }
  applyAccent(readStoredAccent());
}

/** Forces Hedr's default theme/accent for the current page without touching
 * localStorage - the login and signup pages always show the default look, so
 * the user's saved choice is still there to be re-applied after login. */
export function applyDefaultTheme(): void {
  document.documentElement.dataset.theme = "dark";
  document.documentElement.style.removeProperty("--accent");
  document.documentElement.style.removeProperty("--accent-dim");
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

// Every value except "dark" needs an explicit check (dark is the fallback),
// interpolated once at module-eval time from THEME_VALUES so this list can
// never fall out of sync with `isTheme` as themes are added. The result is
// still one fully-deterministic literal string - identical on every server
// render, which inline-script hydration requires - not something built from
// runtime state.
const NON_DEFAULT_VALUES = JSON.stringify(THEME_VALUES.filter((t) => t !== "dark"));

/** Inlined into a blocking <script> in the document head (see layout.tsx) so
 * the right `data-theme` (and, via ACCENT_INIT_SNIPPET, the right accent
 * color) are set before first paint - without this, every page load would
 * flash the wrong theme/accent before React hydrates and corrects them. */
export const THEME_INIT_SCRIPT = `(function(){try{if(/^\\/(login|signup)\\/?$/.test(location.pathname)){document.documentElement.dataset.theme="dark";return;}var t=localStorage.getItem("hedr.theme");var v=${NON_DEFAULT_VALUES};t=(v.indexOf(t)>=0)?t:"dark";document.documentElement.dataset.theme=t;${ACCENT_INIT_SNIPPET}}catch(e){document.documentElement.dataset.theme="dark";}})();`;
