"use client";

import { useCallback, useEffect, useState, type CSSProperties } from "react";
import { useToast } from "@/components/Toast";
import { formatDateTime, timeAgo } from "@/lib/format";
import { api } from "@/lib/api";
import type { MFAStatus, Profile } from "@/lib/types";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { IconLock } from "./icons";
import { MfaModal } from "./MfaModal";

export function AccountSecurityCard({
  profile,
  onPasswordChanged,
  style,
}: {
  profile: Profile;
  onPasswordChanged: () => void;
  style?: CSSProperties;
}) {
  const toast = useToast();
  const [changingPassword, setChangingPassword] = useState(false);
  const [mfa, setMfa] = useState<MFAStatus | null>(null);
  const [mfaModal, setMfaModal] = useState<"enable" | "disable" | null>(null);

  const loadMfa = useCallback(() => {
    api
      .mfaStatus()
      .then(setMfa)
      .catch(() => setMfa(null));
  }, []);
  useEffect(loadMfa, [loadMfa]);

  const passwordChangedAt = profile.password_changed_at;
  const passwordLabel = passwordChangedAt
    ? `Last changed ${timeAgo(passwordChangedAt)}`
    : `Never changed - set since account creation (${formatDateTime(profile.created_at)})`;

  return (
    <div className="panel fade-in-up" id="security" style={style}>
      <h3 className="section-title" style={{ marginTop: 0, marginBottom: 14 }}>
        <span className="section-icon">
          <IconLock />
        </span>
        Account Security
      </h3>

      <div className="value-row" style={{ alignItems: "center" }}>
        <span className="profile-row-icon">
          <IconLock />
        </span>
        <div style={{ flexDirection: "column", display: "flex", gap: 2 }}>
          <span style={{ fontWeight: 600 }}>Password</span>
          <span className="field-hint">{passwordLabel}</span>
        </div>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          style={{ marginLeft: "auto" }}
          onClick={() => setChangingPassword(true)}
        >
          Change Password
        </button>
      </div>

      <div className="value-row" style={{ alignItems: "center", marginTop: 18 }}>
        <span className={`profile-row-icon ${mfa?.enabled ? "" : "is-muted"}`}>
          <IconLock />
        </span>
        <div style={{ flexDirection: "column", display: "flex", gap: 2 }}>
          <span style={{ fontWeight: 600 }}>Two-Factor Authentication</span>
          <span className="field-hint">
            {mfa?.enabled
              ? `Enabled - a verification code is emailed to ${mfa.masked_email} each time you sign in.`
              : "Protect your account with a one-time verification code sent to your registered email address."}
          </span>
          {mfa && !mfa.enabled && !mfa.email_configured && (
            <span className="field-hint" style={{ color: "var(--warn)" }}>
              Email delivery isn&apos;t set up on this server yet, so MFA can&apos;t be enabled.
            </span>
          )}
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
          <span className={`badge ${mfa?.enabled ? "badge-PASS" : "badge-neutral"}`}>
            {mfa === null ? "..." : mfa.enabled ? "Enabled" : "Not enabled"}
          </span>
          {mfa && (
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              disabled={!mfa.enabled && !mfa.email_configured}
              onClick={() => setMfaModal(mfa.enabled ? "disable" : "enable")}
            >
              {mfa.enabled ? "Disable MFA" : "Enable MFA"}
            </button>
          )}
        </div>
      </div>

      {mfaModal && mfa && (
        <MfaModal
          mode={mfaModal}
          maskedEmail={mfa.masked_email}
          onClose={() => setMfaModal(null)}
          onDone={() => {
            const enabled = mfaModal === "enable";
            setMfaModal(null);
            toast.show(enabled ? "Two-factor authentication enabled." : "Two-factor authentication disabled.", "success");
            loadMfa();
          }}
        />
      )}

      {changingPassword && (
        <ChangePasswordModal
          onClose={() => setChangingPassword(false)}
          onChanged={() => {
            setChangingPassword(false);
            toast.show("Password changed.", "success");
            onPasswordChanged();
          }}
        />
      )}
    </div>
  );
}
