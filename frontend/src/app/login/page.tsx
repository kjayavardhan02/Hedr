"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ApiError } from "@/lib/api";
import { Spinner } from "@/components/Spinner";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      router.push("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed unexpectedly.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="container" style={{ maxWidth: 420 }}>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Log in</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Sign in to scan targets and manage your policies.
      </p>

      {error && <div className="error-box">{error}</div>}

      <form className="panel fade-in-up" onSubmit={handleSubmit}>
        <div className="field">
          <label>Email</label>
          <input
            type="email"
            autoComplete="email"
            required
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
        </div>
        <div className="field">
          <label>Password</label>
          <input
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <div style={{ marginTop: 18 }}>
          <button className="btn" type="submit" disabled={submitting}>
            {submitting && <Spinner />}
            {submitting ? "Logging in..." : "Log in"}
          </button>
        </div>
      </form>

      <p className="field-hint" style={{ marginTop: 16 }}>
        Don&apos;t have an account? <Link href="/signup">Sign up</Link>
      </p>
    </div>
  );
}
