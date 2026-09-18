"use client";

import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";

export function AccountMenu() {
  const { user, logout } = useAuth();
  const router = useRouter();

  if (!user) return null;

  async function handleLogout() {
    await logout();
    router.push("/login");
  }

  return (
    <div className="account-menu">
      <span className="account-email">{user.email}</span>
      <button className="btn btn-secondary btn-sm" onClick={handleLogout}>
        Log out
      </button>
    </div>
  );
}
