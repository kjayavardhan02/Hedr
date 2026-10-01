"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { PasswordField } from "@/components/PasswordField";
import { MfaCodeStep } from "@/components/MfaCodeStep";
import { Spinner } from "@/components/Spinner";
import { ApiError, api } from "@/lib/api";
import type { MFACodeIssued } from "@/lib/types";

/** Enable (email -> code) or disable (password -> code) two-factor
 * authentication. Disabling needs the current password AND an emailed code. */
export function MfaModal({
  mode,
  maskedEmail,
  onClose,
  onDone,
}: {
  mode: "enable" | "disable";
  maskedEmail: string;
  onClose: () => void;
  onDone: () => void;
}) {
  const [issued, setIssued] = useState<MFACodeIssued | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [sending, setSending] = useState(false);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const request = () => (mode === "enable" ? api.mfaEnableRequest() : api.mfaDisableRequest(password));

  async function handleSend(e?: React.FormEvent) {
    e?.preventDefault();
    if (mode === "disable" && !password) {
      setError("Enter your current password.");
      return;
    }
    setError(null);
    setSending(true);
    try {
      setIssued(await request());
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Couldn't send a verification code.");
    } finally {
      setSending(false);
    }
  }

  const title = mode === "enable" ? "Enable Multi-Factor Authentication" : "Disable Multi-Factor Authentication";

  return createPortal(
    <div className="modal-overlay fade-in" onClick={onClose}>
      <div
        className="modal-panel fade-in-up"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label={title}
      >
        <div className="modal-header">
          <div className="modal-header-text">
            <h3>{title}</h3>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>

        <div className="modal-body">
          {issued ? (
            <MfaCodeStep
              issued={issued}
              verifyLabel={mode === "enable" ? "Verify and enable" : "Verify and disable"}
              onVerify={async (code) => {
                if (mode === "enable") await api.mfaEnableVerify(code);
                else await api.mfaDisableVerify(code);
                onDone();
              }}
              onResend={async () => {
                const next = await request();
                setIssued(next);
                return next;
              }}
              secondary={
                <button type="button" className="btn btn-secondary" onClick={onClose}>
                  Cancel
                </button>
              }
            />
          ) : (
            <form onSubmit={handleSend}>
              {mode === "enable" ? (
                <p className="mfa-lead">
                  A verification code will be sent to:
                  <br />
                  <strong className="mono">{maskedEmail}</strong>
                </p>
              ) : (
                <>
                  <p className="mfa-lead">
                    To turn two-factor authentication off, confirm your password. We&apos;ll then email a
                    verification code to <strong className="mono">{maskedEmail}</strong>.
                  </p>
                  <PasswordField
                    label="Current password"
                    value={password}
                    onChange={setPassword}
                    autoComplete="current-password"
                  />
                </>
              )}

              {error && <div className="error-box">{error}</div>}

              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={onClose} disabled={sending}>
                  Cancel
                </button>
                <button type="submit" className="btn" disabled={sending}>
                  {sending && <Spinner />}
                  {sending ? "Sending..." : "Send Verification Code"}
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>,
    document.body
  );
}
