"use client";

import { useEffect, useState } from "react";
import { CharCount } from "@/components/CharCount";
import { useToast } from "@/components/Toast";
import { ApiError, api } from "@/lib/api";
import {
  JOB_TITLE_MAX_LENGTH,
  ORGANIZATION_MAX_LENGTH,
  PERSON_NAME_MAX_LENGTH,
  USERNAME_MAX_LENGTH,
} from "@/lib/limits";
import type { Profile } from "@/lib/types";

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="value-row" style={{ flexDirection: "column", alignItems: "flex-start", gap: 2 }}>
      <span className="field-hint">{label}</span>
      <span style={{ fontSize: 15 }}>{value}</span>
    </div>
  );
}

export function PersonalInformationCard({
  profile,
  onUpdated,
  editSignal,
}: {
  profile: Profile;
  onUpdated: (profile: Profile) => void;
  /** Bumped by the Profile Overview's "Edit Profile" button to jump straight
   * into edit mode here, without lifting all the form state up a level. */
  editSignal?: number;
}) {
  const toast = useToast();
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [firstName, setFirstName] = useState(profile.first_name);
  const [lastName, setLastName] = useState(profile.last_name);
  const [username, setUsername] = useState(profile.username ?? "");
  const [organization, setOrganization] = useState(profile.organization ?? "");
  const [jobTitle, setJobTitle] = useState(profile.job_title ?? "");

  function startEditing() {
    setFirstName(profile.first_name);
    setLastName(profile.last_name);
    setUsername(profile.username ?? "");
    setOrganization(profile.organization ?? "");
    setJobTitle(profile.job_title ?? "");
    setError(null);
    setEditing(true);
  }

  useEffect(() => {
    if (editSignal) startEditing();
    // Only `editSignal` itself should re-trigger this - `startEditing` reads
    // the latest `profile` each time it's actually called.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editSignal]);

  async function handleSave() {
    setError(null);
    if (!firstName.trim() || !lastName.trim()) {
      setError("First and last name can't be blank.");
      return;
    }
    setSaving(true);
    try {
      const updated = await api.updateProfile({
        first_name: firstName.trim(),
        last_name: lastName.trim(),
        username: username.trim(),
        organization: organization.trim(),
        job_title: jobTitle.trim(),
      });
      onUpdated(updated);
      setEditing(false);
      toast.show("Profile updated.", "success");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Couldn't save your changes.");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="panel fade-in-up" id="personal-info">
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
        <h3 style={{ marginTop: 0, marginBottom: 4, fontSize: 16 }}>Personal Information</h3>
        {!editing && (
          <button type="button" className="btn btn-secondary btn-sm" onClick={startEditing}>
            Edit
          </button>
        )}
      </div>

      {editing ? (
        <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 10 }}>
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            <div className="field" style={{ flex: 1, minWidth: 160 }}>
              <label>Full Name</label>
              <input
                value={firstName}
                maxLength={PERSON_NAME_MAX_LENGTH}
                onChange={(e) => setFirstName(e.target.value)}
                placeholder="First name"
              />
            </div>
            <div className="field" style={{ flex: 1, minWidth: 160, marginTop: 22 }}>
              <input
                value={lastName}
                maxLength={PERSON_NAME_MAX_LENGTH}
                onChange={(e) => setLastName(e.target.value)}
                placeholder="Last name"
              />
            </div>
          </div>
          <div className="field">
            <label>Email Address</label>
            <input value={profile.email} disabled />
            <span className="field-hint">Contact support to change the email on your account.</span>
          </div>
          <div className="field">
            <label>Username</label>
            <input
              value={username}
              maxLength={USERNAME_MAX_LENGTH}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Not specified"
            />
            <CharCount length={username.length} max={USERNAME_MAX_LENGTH} showFrom={0.8} />
          </div>
          <div className="field">
            <label>Organization</label>
            <input
              value={organization}
              maxLength={ORGANIZATION_MAX_LENGTH}
              onChange={(e) => setOrganization(e.target.value)}
              placeholder="Not specified"
            />
            <CharCount length={organization.length} max={ORGANIZATION_MAX_LENGTH} showFrom={0.8} />
          </div>
          <div className="field">
            <label>Job Title</label>
            <input
              value={jobTitle}
              maxLength={JOB_TITLE_MAX_LENGTH}
              onChange={(e) => setJobTitle(e.target.value)}
              placeholder="Not specified"
            />
            <CharCount length={jobTitle.length} max={JOB_TITLE_MAX_LENGTH} showFrom={0.8} />
          </div>

          {error && <div className="error-box">{error}</div>}

          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
            <button type="button" className="btn btn-secondary" onClick={() => setEditing(false)} disabled={saving}>
              Cancel
            </button>
            <button type="button" className="btn" onClick={handleSave} disabled={saving}>
              {saving ? "Saving..." : "Save"}
            </button>
          </div>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 14, marginTop: 10 }}>
          <Field label="Full Name" value={`${profile.first_name} ${profile.last_name}`} />
          <Field label="Email Address" value={profile.email} />
          <Field label="Username" value={profile.username ?? "Not specified"} />
          <Field label="Organization" value={profile.organization ?? "Not specified"} />
          <Field label="Job Title" value={profile.job_title ?? "Not specified"} />
        </div>
      )}
    </div>
  );
}
