import type { Theme } from "./theme";

export type AccentColor = "default" | "cyan" | "blue" | "purple" | "green" | "pink" | "orange";

const STORAGE_KEY = "hedr.accent";

/** Accent hex values per color, split by light/dark theme family since a
 * single hex rarely has good contrast against both a near-black and a
 * near-white background. "default" has no entry here - it means "use
 * whatever --accent/--accent-dim the active theme already defines", so
 * applying it is just removing any override rather than setting one.
 * "orange" intentionally matches Dark's and Light's own built-in accent
 * (see globals.css) - picking it explicitly reproduces the original look. */
const ACCENT_VALUES: Record<
  Exclude<AccentColor, "default">,
  { dark: { accent: string; dim: string }; light: { accent: string; dim: string } }
> = {
  cyan: { dark: { accent: "#22d3ee", dim: "#0e7490" }, light: { accent: "#0891c2", dim: "#066a92" } },
  blue: { dark: { accent: "#5b8cff", dim: "#3a56b8" }, light: { accent: "#1d5fd1", dim: "#15449e" } },
  purple: { dark: { accent: "#a78bfa", dim: "#6d28d9" }, light: { accent: "#7c3aed", dim: "#5b21b6" } },
  green: { dark: { accent: "#22c55e", dim: "#15803d" }, light: { accent: "#15803d", dim: "#166534" } },
  pink: { dark: { accent: "#f472b6", dim: "#be185d" }, light: { accent: "#be185d", dim: "#9d174d" } },
  orange: { dark: { accent: "#ff7a1a", dim: "#b35513" }, light: { accent: "#e8630a", dim: "#b34c0a" } },
};

/** Display metadata for every non-"default" accent, for the color-dot picker. */
export const ACCENT_COLORS: { id: Exclude<AccentColor, "default">; name: string; swatch: string }[] = [
  { id: "cyan", name: "Cyan", swatch: ACCENT_VALUES.cyan.dark.accent },
  { id: "blue", name: "Blue", swatch: ACCENT_VALUES.blue.dark.accent },
  { id: "purple", name: "Purple", swatch: ACCENT_VALUES.purple.dark.accent },
  { id: "green", name: "Green", swatch: ACCENT_VALUES.green.dark.accent },
  { id: "pink", name: "Pink", swatch: ACCENT_VALUES.pink.dark.accent },
  { id: "orange", name: "Orange", swatch: ACCENT_VALUES.orange.dark.accent },
];

/** Per spec section 7: each theme curates a small subset of accents that
 * actually fit its palette, rather than offering all 6 everywhere. "default"
 * (that theme's own built-in accent) is always first. */
const ACCENT_CHOICES_BY_THEME: Record<Theme, AccentColor[]> = {
  dark: ["default", "blue", "purple"],
  light: ["default", "blue", "green"],
  offwhite: ["default", "blue", "pink", "orange"],
  cyberpunk: ["default", "purple", "pink"],
  terminal: ["default", "cyan", "orange"],
  midnight: ["default", "blue", "pink"],
  arctic: ["default", "blue", "purple"],
  dracula: ["default", "pink", "cyan"],
  forest: ["default", "green", "cyan"],
  sunset: ["default", "orange", "purple"],
  lavender: ["default", "pink", "blue"],
};

const LIGHT_FAMILY_THEMES = ["light", "offwhite", "arctic", "lavender"];

function isAccentColor(value: string | null): value is AccentColor {
  return value === "default" || (value !== null && value in ACCENT_VALUES);
}

function resolveIsLight(dataTheme: string): boolean {
  return LIGHT_FAMILY_THEMES.includes(dataTheme);
}

/** The curated accent list for a theme. */
export function getAccentChoicesForTheme(theme: Theme): AccentColor[] {
  return ACCENT_CHOICES_BY_THEME[theme];
}

/** Sets --accent/--accent-dim as inline styles on <html> (highest
 * specificity, so they win over whatever the active theme's own CSS block
 * defines) and remembers the choice in localStorage. "default" clears the
 * override instead, letting the theme's own values show through again. */
export function applyAccent(accent: AccentColor): void {
  const dataTheme = document.documentElement.dataset.theme ?? "dark";
  const rootStyle = document.documentElement.style;
  if (accent === "default") {
    rootStyle.removeProperty("--accent");
    rootStyle.removeProperty("--accent-dim");
  } else {
    const values = ACCENT_VALUES[accent][resolveIsLight(dataTheme) ? "light" : "dark"];
    rootStyle.setProperty("--accent", values.accent);
    rootStyle.setProperty("--accent-dim", values.dim);
  }
  try {
    localStorage.setItem(STORAGE_KEY, accent);
  } catch {
    // Storage unavailable - still applies for this load, just not remembered.
  }
}

export function readStoredAccent(): AccentColor {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (isAccentColor(stored)) return stored;
  } catch {
    // ignore
  }
  return "default";
}

// Inlined into the same blocking pre-hydration <script> theme.ts builds, so
// a non-default accent is applied before first paint too - otherwise every
// load would flash the active theme's own accent before React corrects it.
// Built from ACCENT_VALUES/LIGHT_FAMILY_THEMES above (JSON.stringify at
// module-eval time, so it's still one fully-deterministic literal string)
// rather than hand-duplicated, so it can't drift out of sync as accents are
// added. Expects `t` (the already-resolved theme value) to be in scope.
export const ACCENT_INIT_SNIPPET = `var a=localStorage.getItem("${STORAGE_KEY}");var av=${JSON.stringify(
  ACCENT_VALUES
)};if(a&&a!=="default"&&av[a]){var isLight=${JSON.stringify(
  LIGHT_FAMILY_THEMES
)}.indexOf(t)>=0;var v=av[a][isLight?"light":"dark"];document.documentElement.style.setProperty("--accent",v.accent);document.documentElement.style.setProperty("--accent-dim",v.dim);}`;
