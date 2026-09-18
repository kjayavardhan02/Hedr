"use client";

import { useEffect } from "react";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { Spinner } from "@/components/Spinner";

const PUBLIC_PATHS = new Set(["/login", "/signup"]);

export function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuth();
  const pathname = usePathname();
  const router = useRouter();
  const isPublicPath = pathname !== null && PUBLIC_PATHS.has(pathname);

  useEffect(() => {
    if (loading) return;
    if (!user && !isPublicPath) {
      router.replace("/login");
    } else if (user && isPublicPath) {
      router.replace("/");
    }
  }, [loading, user, isPublicPath, router]);

  if (isPublicPath) {
    return loading || !user ? <>{children}</> : null;
  }

  if (loading || !user) {
    return (
      <div className="container" style={{ display: "flex", justifyContent: "center", padding: "60px 0" }}>
        <Spinner />
      </div>
    );
  }

  return <>{children}</>;
}
