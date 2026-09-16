"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

export function NavLinks() {
  const pathname = usePathname();
  const isScan = pathname === "/";
  const isPolicies = pathname?.startsWith("/policies");

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
