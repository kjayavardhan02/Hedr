"use client";

import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth-context";
import { ApiError } from "@/lib/api";
import { Spinner } from "@/components/Spinner";

export default function SignupPage() {
  const router = useRouter();
  const { register } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords don't match.");
      return;
    }

    setSubmitting(true);
    try {
      await register(email.trim(), password);
      router.push("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign up failed unexpectedly.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="container" style={{ maxWidth: 420 }}>
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Create an account</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Your policies are private to your account - no one else can view, use, or
        edit them.
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
            autoComplete="new-password"
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <span className="field-hint">At least 8 characters.</span>
        </div>
        <div className="field">
          <label>Confirm password</label>
          <input
            type="password"
            autoComplete="new-password"
            required
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
          />
        </div>
        <div style={{ marginTop: 18 }}>
          <button className="btn" type="submit" disabled={submitting}>
            {submitting && <Spinner />}
            {submitting ? "Creating account..." : "Sign up"}
          </button>
        </div>
      </form>

      <p className="field-hint" style={{ marginTop: 16 }}>
        Already have an account? <Link href="/login">Log in</Link>
      </p>
    </div>
  );
}
