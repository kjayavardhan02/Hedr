"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { capitalize } from "@/lib/format";
import { ShieldLogo } from "@/components/ShieldLogo";

const HIDDEN_PATHS = new Set(["/login", "/signup"]);

const NAV_ITEMS = [
  {
    href: "/dashboard",
    label: "Dashboard",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <rect x="3.5" y="3.5" width="7.5" height="7.5" rx="1.6" stroke="currentColor" strokeWidth="1.6" />
        <rect x="13" y="3.5" width="7.5" height="4.5" rx="1.6" stroke="currentColor" strokeWidth="1.6" />
        <rect x="13" y="10.5" width="7.5" height="10" rx="1.6" stroke="currentColor" strokeWidth="1.6" />
        <rect x="3.5" y="13.5" width="7.5" height="7" rx="1.6" stroke="currentColor" strokeWidth="1.6" />
      </svg>
    ),
  },
  {
    href: "/scan",
    label: "Scan",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6" />
        <path d="M20.5 20.5 16 16" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    ),
  },
  {
    href: "/policies",
    label: "Policies",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path
          d="M12 3 5 5.8v5.4c0 5 3.2 8.8 7 10.8 3.8-2 7-5.8 7-10.8V5.8L12 3Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
      </svg>
    ),
  },
  {
    href: "/reports",
    label: "Reports",
    icon: (
      <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path
          d="M6 3.5h9l3.5 3.5V20a.5.5 0 0 1-.5.5H6a.5.5 0 0 1-.5-.5V4a.5.5 0 0 1 .5-.5Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path d="M8.5 12h7M8.5 15.5h7M8.5 8.5h3.5" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      </svg>
    ),
  },
];

function initials(firstName: string, lastName: string): string {
  return `${firstName.charAt(0)}${lastName.charAt(0)}`.toUpperCase();
}

function Avatar({ userId, firstName, lastName }: { userId: string; firstName: string; lastName: string }) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return <div className="sidebar-avatar">{initials(firstName, lastName)}</div>;
  }

  return (
    <div className="sidebar-avatar">
      <img
        src={`https://api.dicebear.com/9.x/avataaars/svg?seed=${encodeURIComponent(userId)}`}
        alt=""
        aria-hidden="true"
        onError={() => setFailed(true)}
      />
    </div>
  );
}

export function Sidebar() {
  const { user, logout } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close the drawer whenever the route changes (link clicks, back/forward).
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  // Lock background scroll while the mobile drawer is open.
  useEffect(() => {
    document.body.style.overflow = mobileOpen ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [mobileOpen]);

  if (pathname !== null && HIDDEN_PATHS.has(pathname)) return null;
  if (!user) return null;

  async function handleLogout() {
    await logout();
    router.push("/login");
  }

  return (
    <>
      <div className="mobile-topbar">
        <Link href="/dashboard" className="brand">
          <ShieldLogo />
          Hedr
        </Link>
        <button
          type="button"
          className="hamburger-btn"
          aria-label={mobileOpen ? "Close menu" : "Open menu"}
          aria-expanded={mobileOpen}
          onClick={() => setMobileOpen((v) => !v)}
        >
          {mobileOpen ? (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M6 6l12 12M18 6 6 18" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          ) : (
            <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <path d="M4 7h16M4 12h16M4 17h16" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
            </svg>
          )}
        </button>
      </div>

      {mobileOpen && <div className="sidebar-backdrop" onClick={() => setMobileOpen(false)} />}

      <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
        <Link href="/dashboard" className="brand">
          <ShieldLogo />
          Hedr
        </Link>

        <div className="sidebar-profile">
          <Avatar userId={user.id} firstName={user.first_name} lastName={user.last_name} />
          <div className="sidebar-profile-info">
            <div className="sidebar-profile-name">
              {capitalize(user.first_name)} {capitalize(user.last_name)}
            </div>
            <div className="sidebar-profile-email">{user.email}</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {NAV_ITEMS.map((item) => {
            const active =
              item.href === "/policies" || item.href === "/reports"
                ? pathname?.startsWith(item.href)
                : pathname === item.href;
            return (
              <Link key={item.href} href={item.href} className={`sidebar-link ${active ? "active" : ""}`}>
                {item.icon}
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="sidebar-footer">
          <button className="btn btn-secondary" onClick={handleLogout}>
            Log out
          </button>
        </div>
      </aside>
    </>
  );
}
