"use client";

import { useEffect, useState } from "react";
import { ApiError } from "@/lib/api";
import { formatClock, useCountdown } from "@/lib/useCountdown";
import type { MFACodeIssued } from "@/lib/types";
import { OTP_LENGTH, OtpInput } from "./OtpInput";
import { Spinner } from "./Spinner";

/** The "enter the code we emailed you" step, shared by the sign-in page and
 * the enable/disable modals: code boxes, Verify, a resend with cooldown, and
 * a live expiry countdown. The caller decides what verifying does. */
export function MfaCodeStep({
  issued,
  onVerify,
  onResend,
  verifyLabel = "Verify",
  secondary,
}: {
  issued: MFACodeIssued;
  onVerify: (code: string) => Promise<void>;
  onResend: () => Promise<MFACodeIssued>;
  verifyLabel?: string;
  /** Extra button(s) rendered beside Verify (e.g. Cancel). */
  secondary?: React.ReactNode;
}) {
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [resending, setResending] = useState(false);
  const [expiresIn, startExpiry] = useCountdown(issued.expires_in);
  const [resendIn, startResend] = useCountdown(issued.resend_available_in);
  const [maskedEmail, setMaskedEmail] = useState(issued.masked_email);
  // Bumped after a failed attempt so the boxes remount, empty and focused.
  const [resetKey, setResetKey] = useState(0);

  // A new `issued` (e.g. the parent swapped in a re-sent challenge) restarts both clocks.
  useEffect(() => {
    startExpiry(issued.expires_in);
    startResend(issued.resend_available_in);
    setMaskedEmail(issued.masked_email);
  }, [issued, startExpiry, startResend]);

  async function handleVerify(e?: React.FormEvent) {
    e?.preventDefault();
    if (code.length !== OTP_LENGTH || verifying) return;
    setError(null);
    setVerifying(true);
    try {
      await onVerify(code);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't verify the code.");
      setCode("");
      setResetKey((k) => k + 1);
    } finally {
      setVerifying(false);
    }
  }

  async function handleResend() {
    setError(null);
    setResending(true);
    try {
      const next = await onResend();
      setCode("");
      setMaskedEmail(next.masked_email);
      startExpiry(next.expires_in);
      startResend(next.resend_available_in);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't send a new code.");
    } finally {
      setResending(false);
    }
  }

  const expired = expiresIn <= 0;

  return (
    <form onSubmit={handleVerify}>
      <p className="mfa-lead">
        We&apos;ve sent a {OTP_LENGTH}-digit verification code to:
        <br />
        <strong className="mono">{maskedEmail}</strong>
      </p>

      <div className="field">
        <label>Verification code</label>
        <OtpInput key={resetKey} value={code} onChange={setCode} disabled={verifying} invalid={Boolean(error)} />
        <span className={`field-hint ${expired ? "mfa-expired" : ""}`}>
          {expired ? "This code has expired. Request a new one below." : `Code expires in ${formatClock(expiresIn)}`}
        </span>
      </div>

      {error && <div className="error-box">{error}</div>}

      <div className="mfa-actions">
        <button className="btn" type="submit" disabled={verifying || code.length !== OTP_LENGTH || expired}>
          {verifying && <Spinner />}
          {verifying ? "Verifying..." : verifyLabel}
        </button>
        {secondary}
      </div>

      <div className="mfa-resend">
        <span className="field-hint">Didn&apos;t receive it?</span>
        <button
          type="button"
          className="link-button"
          onClick={handleResend}
          disabled={resending || resendIn > 0}
        >
          {resending ? "Sending..." : resendIn > 0 ? `Resend available in ${resendIn}s` : "Resend code"}
        </button>
      </div>
    </form>
  );
}
