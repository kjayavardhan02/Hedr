"use client";

import { useId, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ApiError } from "@/lib/api";
import { Spinner } from "@/components/Spinner";
import { AuthLayout } from "@/components/AuthLayout";
import { PasswordField } from "@/components/PasswordField";

function passwordStrength(password: string): { label: string; level: number } {
  if (!password) return { label: "", level: 0 };
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (/[0-9]/.test(password) && /[a-zA-Z]/.test(password)) score++;
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  const labels = ["Too short", "Weak", "Okay", "Good", "Strong"];
  return { label: labels[score], level: score };
}

export default function SignupPage() {
  const router = useRouter();
  const { register } = useAuth();
  const emailId = useId();
  const firstNameId = useId();
  const lastNameId = useId();
  const [firstName, setFirstName] = useState("");
  const [lastName, setLastName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [shake, setShake] = useState(false);

  const strength = passwordStrength(password);

  function fail(message: string) {
    setError(message);
    setShake(true);
    setTimeout(() => setShake(false), 400);
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!firstName.trim() || !lastName.trim()) {
      fail("Enter your first and last name.");
      return;
    }
    if (password.length < 8) {
      fail("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      fail("Passwords don't match.");
      return;
    }

    setSubmitting(true);
    try {
      await register(email.trim(), password, firstName.trim(), lastName.trim());
      router.push("/dashboard");
    } catch (err) {
      fail(err instanceof ApiError ? err.message : "Sign up failed unexpectedly.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="Your policies are private — no one else can view, use, or edit them."
      footer={
        <>
          Already have an account? <Link href="/login">Log in</Link>
        </>
      }
    >
      {error && <div className={`error-box ${shake ? "shake" : ""}`}>{error}</div>}

      <form onSubmit={handleSubmit}>
        <div className="row" style={{ gap: 12 }}>
          <div className="field" style={{ flex: 1, minWidth: 140 }}>
            <label htmlFor={firstNameId}>First name</label>
            <input
              id={firstNameId}
              type="text"
              autoComplete="given-name"
              placeholder="Ada"
              required
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
            />
          </div>
          <div className="field" style={{ flex: 1, minWidth: 140 }}>
            <label htmlFor={lastNameId}>Last name</label>
            <input
              id={lastNameId}
              type="text"
              autoComplete="family-name"
              placeholder="Lovelace"
              required
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
            />
          </div>
        </div>

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
          autoComplete="new-password"
          minLength={8}
          placeholder="Create a password"
        />

        {password && (
          <div className="password-strength" style={{ marginTop: -8 }}>
            <div className="password-strength-track">
              {[0, 1, 2, 3].map((i) => (
                <span
                  key={i}
                  className={`password-strength-bar ${i < strength.level ? `level-${strength.level}` : ""}`}
                />
              ))}
            </div>
            <span className="field-hint">{strength.label}</span>
          </div>
        )}

        <PasswordField
          label="Confirm password"
          value={confirmPassword}
          onChange={setConfirmPassword}
          autoComplete="new-password"
          placeholder="Re-enter your password"
        />

        <button className="btn btn-block" type="submit" disabled={submitting}>
          {submitting && <Spinner />}
          {submitting ? "Creating account..." : "Sign up"}
        </button>
      </form>
    </AuthLayout>
  );
}
