"use client";

import { useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ApiError } from "@/lib/api";
import { Spinner } from "@/components/Spinner";
import { AuthLayout } from "@/components/AuthLayout";
import { PasswordField } from "@/components/PasswordField";

export default function LoginPage() {
  const router = useRouter();
  const { login } = useAuth();
  const emailId = useId();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email.trim(), password);
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed unexpectedly.");
      setShake(true);
      setTimeout(() => setShake(false), 400);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout
      title="Welcome back"
      subtitle="Log in to scan targets and manage your policies."
      footer={
        <>
          Don&apos;t have an account? <Link href="/signup">Sign up — it&apos;s free</Link>
        </>
      }
    >
      {error && <div className={`error-box ${shake ? "shake" : ""}`}>{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="field">
          <label htmlFor={emailId}>Email</label>
          <div className="input-icon-wrap">
            <svg className="input-icon" viewBox="0 0 24 24" fill="none" aria-hidden="true">
              <rect x="3.5" y="5.5" width="17" height="13" rx="2.2" stroke="currentColor" strokeWidth="1.6" />
              <path d="M4.5 7 12 12.5 19.5 7" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
            <input
              id={emailId}
              type="email"
              className="has-icon"
              autoComplete="email"
              placeholder="you@example.com"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
        </div>

        <PasswordField
          label="Password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
          placeholder="Enter your password"
        />

        <button className="btn btn-block" type="submit" disabled={submitting}>
          {submitting && <Spinner />}
          {submitting ? "Logging in..." : "Log in"}
        </button>
      </form>
    </AuthLayout>
  );
}
