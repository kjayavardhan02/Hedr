"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useAuth } from "@/lib/auth-context";

export function NavLinks() {
  const pathname = usePathname();
  const { user } = useAuth();
  const isScan = pathname === "/";
  const isPolicies = pathname?.startsWith("/policies");

  if (!user) return null;

  return (
    <div className="nav-links">
      <Link href="/" className={isScan ? "active" : ""}>
        Scan
      </Link>
      <Link href="/policies" className={isPolicies ? "active" : ""}>
        Policies
      </Link>
    </div>
  );
}
