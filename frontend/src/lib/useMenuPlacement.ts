import { type RefObject, useCallback, useLayoutEffect, useState } from "react";

const VIEWPORT_GAP = 16;

/** Where a dropdown menu should open: below its trigger, or above it when there
 * is more room there, and never taller than the space available. Re-measured on
 * scroll and resize while open. */
export function useMenuPlacement(
  open: boolean,
  triggerRef: RefObject<HTMLElement | null>,
  { maxHeight = 400, minHeight = 220 }: { maxHeight?: number; minHeight?: number } = {}
) {
  const [placement, setPlacement] = useState({ up: false, maxHeight });

  const place = useCallback(() => {
    const rect = triggerRef.current?.getBoundingClientRect();
    if (!rect) return;
    const below = window.innerHeight - rect.bottom - VIEWPORT_GAP;
    const above = rect.top - VIEWPORT_GAP;
    const up = below < minHeight && above > below;
    const room = up ? above : below;
    setPlacement({ up, maxHeight: Math.max(160, Math.min(maxHeight, room)) });
  }, [triggerRef, maxHeight, minHeight]);

  useLayoutEffect(() => {
    if (!open) return;
    place();
    window.addEventListener("resize", place);
    window.addEventListener("scroll", place, true);
    return () => {
      window.removeEventListener("resize", place);
      window.removeEventListener("scroll", place, true);
    };
  }, [open, place]);

  return placement;
}
