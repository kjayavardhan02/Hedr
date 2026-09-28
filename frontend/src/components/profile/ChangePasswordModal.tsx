"use client";

import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import { PasswordField } from "@/components/PasswordField";
import { passwordStrength } from "@/lib/format";
import { NEW_PASSWORD_MIN_LENGTH } from "@/lib/limits";
import { ApiError, api } from "@/lib/api";

export function ChangePasswordModal({ onClose, onChanged }: { onClose: () => void; onChanged: () => void }) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const strength = passwordStrength(newPassword);

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (newPassword.length < NEW_PASSWORD_MIN_LENGTH) {
      setError(`New password must be at least ${NEW_PASSWORD_MIN_LENGTH} characters.`);
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New passwords don't match.");
      return;
    }

    setSaving(true);
    try {
      await api.changePassword({ current_password: currentPassword, new_password: newPassword });
      onChanged();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't change your password.");
    } finally {
      setSaving(false);
    }
  }

  return createPortal(
    <div className="modal-overlay fade-in" onClick={onClose}>
      <div
        className="modal-panel fade-in-up"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-modal="true"
        aria-label="Change password"
      >
        <div className="modal-header">
          <div className="modal-header-text">
            <h3>Change Password</h3>
          </div>
          <button type="button" className="modal-close" onClick={onClose} aria-label="Close">
            ✕
          </button>
        </div>
        <form onSubmit={handleSubmit} className="modal-body" style={{ display: "flex", flexDirection: "column", gap: 4 }}>
          <PasswordField
            label="Current password"
            value={currentPassword}
            onChange={setCurrentPassword}
            autoComplete="current-password"
          />
          <PasswordField
            label="New password"
            value={newPassword}
            onChange={setNewPassword}
            autoComplete="new-password"
            minLength={NEW_PASSWORD_MIN_LENGTH}
          />
          {newPassword && (
            <div className="password-strength" style={{ marginTop: -8, marginBottom: 4 }}>
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
            label="Confirm new password"
            value={confirmPassword}
            onChange={setConfirmPassword}
            autoComplete="new-password"
          />

          {error && <div className="error-box">{error}</div>}

          <div className="modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose} disabled={saving}>
              Cancel
            </button>
            <button type="submit" className="btn" disabled={saving}>
              {saving ? "Changing..." : "Change Password"}
            </button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  );
}
