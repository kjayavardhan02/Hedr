"use client";

import { useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import type { User } from "@/lib/types";

/** The dropdown opened by clicking the sidebar's user card: Profile /
 * Account Security / Sign out. Closes on an outside click, Escape, or after
 * an item is chosen - never left open across a navigation. */
export function AccountMenu({
  user,
  onClose,
  onSignOut,
}: {
  user: User;
  onClose: () => void;
  onSignOut: () => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const router = useRouter();

  useEffect(() => {
    function onPointerDown(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [onClose]);

  function go(href: string) {
    onClose();
    router.push(href);
  }

  return (
    <div className="account-menu" ref={ref} role="menu">
      <div className="account-menu-header">
        <div className="sidebar-profile-name">{user.first_name} {user.last_name}</div>
        <div className="sidebar-profile-email">{user.email}</div>
      </div>
      <div className="account-menu-divider" />
      <button type="button" className="account-menu-item" role="menuitem" onClick={() => go("/profile")}>
        Profile
      </button>
      <button
        type="button"
        className="account-menu-item"
        role="menuitem"
        onClick={() => go("/profile#security")}
      >
        Account Security
      </button>
      <div className="account-menu-divider" />
      <button
        type="button"
        className="account-menu-item account-menu-item-danger"
        role="menuitem"
        onClick={() => {
          onClose();
          onSignOut();
        }}
      >
        Sign out
      </button>
    </div>
  );
}
