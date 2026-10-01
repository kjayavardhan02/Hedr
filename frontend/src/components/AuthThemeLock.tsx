"use client";

import { useLayoutEffect } from "react";
import { applyDefaultTheme } from "@/lib/theme";

/** Pins the login/signup pages to the default theme, whatever the user last
 * picked in their profile. Doesn't touch the stored preference, so it's
 * re-applied on login. */
export function AuthThemeLock() {
  useLayoutEffect(() => {
    applyDefaultTheme();
  }, []);
  return null;
}
