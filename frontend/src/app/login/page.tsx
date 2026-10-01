"use client";

import { useEffect, useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ApiError, api } from "@/lib/api";
import type { MFALoginChallenge } from "@/lib/types";
import { MfaCodeStep } from "@/components/MfaCodeStep";
import { Spinner } from "@/components/Spinner";
import { AuthLayout } from "@/components/AuthLayout";
import { PasswordField } from "@/components/PasswordField";

export default function LoginPage() {
  const router = useRouter();
  const { login, completeMfaLogin } = useAuth();
  const emailId = useId();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  // Arriving from signup: the account exists but nobody is signed in yet.
  const [justRegistered, setJustRegistered] = useState(false);
  useEffect(() => {
    setJustRegistered(new URLSearchParams(window.location.search).get("registered") === "1");
  }, []);
  // Set once the password was right but the account needs an emailed code.
  const [challenge, setChallenge] = useState<MFALoginChallenge | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const pending = await login(email.trim(), password);
      if (pending) {
        setChallenge(pending);
        return;
      }
      router.push("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed unexpectedly.");
      setShake(true);
      setTimeout(() => setShake(false), 400);
    } finally {
      setSubmitting(false);
    }
  }

  if (challenge) {
    return (
      <AuthLayout
        title="Verify your identity"
        subtitle="Two-factor authentication is turned on for this account."
        footer={<>Wrong account? <a href="/login">Back to log in</a></>}
      >
        <MfaCodeStep
          issued={challenge}
          verifyLabel="Verify"
          onVerify={async (code) => {
            await completeMfaLogin(challenge.challenge_id, code);
            router.push("/dashboard");
          }}
          onResend={async () => {
            const next = await api.mfaLoginResend(challenge.challenge_id);
            setChallenge(next);
            return next;
          }}
          secondary={
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => {
                setChallenge(null);
                setPassword("");
              }}
            >
              Back
            </button>
          }
        />
      </AuthLayout>
    );
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
      {justRegistered && !error && (
        <div className="success-box" role="status">
          Account created. Log in to continue.
        </div>
      )}
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
