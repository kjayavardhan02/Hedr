"use client";

import { useState, type CSSProperties } from "react";
import { useToast } from "@/components/Toast";
import { formatDateTime, timeAgo } from "@/lib/format";
import type { Profile } from "@/lib/types";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { IconLock } from "./icons";

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
        <span className="profile-row-icon is-muted">
          <IconLock />
        </span>
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
