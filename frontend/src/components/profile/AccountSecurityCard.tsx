"use client";

import { useState } from "react";
import { useToast } from "@/components/Toast";
import { formatDateTime, timeAgo } from "@/lib/format";
import type { Profile } from "@/lib/types";
import { ChangePasswordModal } from "./ChangePasswordModal";

export function AccountSecurityCard({
  profile,
  onPasswordChanged,
}: {
  profile: Profile;
  onPasswordChanged: () => void;
}) {
  const toast = useToast();
  const [changingPassword, setChangingPassword] = useState(false);

  const passwordChangedAt = profile.password_changed_at;
  const passwordLabel = passwordChangedAt
    ? `Last changed ${timeAgo(passwordChangedAt)}`
    : `Never changed - set since account creation (${formatDateTime(profile.created_at)})`;

  return (
    <div className="panel fade-in-up" id="security">
      <h3 style={{ marginTop: 0, marginBottom: 12, fontSize: 16 }}>Account Security</h3>

      <div className="value-row" style={{ alignItems: "center" }}>
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

      <div className="value-row" style={{ alignItems: "center", marginTop: 16 }}>
        <div style={{ flexDirection: "column", display: "flex", gap: 2 }}>
          <span style={{ fontWeight: 600 }}>Two-Factor Authentication</span>
          <span className="field-hint">Not enabled</span>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
          <span className="badge badge-INFO">Coming soon</span>
          <button type="button" className="btn btn-secondary btn-sm" disabled title="Coming soon">
            Enable 2FA
          </button>
        </div>
      </div>

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
