"use client";

import { useEffect, useState } from "react";
import { Avatar } from "@/components/Avatar";
import { AccountSecurityCard } from "@/components/profile/AccountSecurityCard";
import { ComingSoonCard } from "@/components/profile/ComingSoonCard";
import { PersonalInformationCard } from "@/components/profile/PersonalInformationCard";
import { PreferencesCard } from "@/components/profile/PreferencesCard";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { useAuth } from "@/lib/auth-context";
import { api, ApiError } from "@/lib/api";
import { capitalize, formatMonthYear } from "@/lib/format";
import type { Profile } from "@/lib/types";

export default function ProfilePage() {
  const { refreshUser } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editSignal, setEditSignal] = useState(0);

  function load() {
    api
      .getProfile()
      .then(setProfile)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Couldn't load your profile."));
  }

  useEffect(load, []);

  // Jump straight to the Account Security card when arriving via the
  // sidebar's "Account Security" menu item (a /profile#security link).
  useEffect(() => {
    if (window.location.hash === "#security") {
      document.getElementById("security")?.scrollIntoView({ block: "start" });
    }
  }, [profile]);

  async function handleProfileUpdated(updated: Profile) {
    setProfile(updated);
    await refreshUser();
  }

  async function handlePasswordChanged() {
    load();
  }

  if (error) {
    return (
      <div className="container">
        <div className="error-box">{error}</div>
      </div>
    );
  }

  if (!profile) {
    return (
      <div className="container">
        <PolicyFormSkeleton />
      </div>
    );
  }

  return (
    <div className="container">
      <h1 style={{ fontSize: 24, marginBottom: 20 }}>Profile</h1>

      <div className="panel fade-in-up profile-overview">
        <Avatar userId={profile.id} firstName={profile.first_name} lastName={profile.last_name} size={84} />
        <div className="profile-overview-name">
          {capitalize(profile.first_name)} {capitalize(profile.last_name)}
        </div>
        <div className="field-hint">{profile.email}</div>
        <div className="field-hint" style={{ marginTop: 4 }}>
          Member since {formatMonthYear(profile.created_at)}
        </div>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          style={{ marginTop: 14 }}
          onClick={() => setEditSignal((n) => n + 1)}
        >
          Edit Profile
        </button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 16 }}>
        <PersonalInformationCard profile={profile} onUpdated={handleProfileUpdated} editSignal={editSignal} />
        <AccountSecurityCard profile={profile} onPasswordChanged={handlePasswordChanged} />
        <ComingSoonCard
          id="api-keys"
          title="API Keys"
          description="Use API keys to integrate Hedr with CI/CD pipelines and other tools. Coming soon."
        />
        <PreferencesCard defaultPolicyId={profile.default_policy_id} />
        <ComingSoonCard
          id="notifications"
          title="Notifications"
          description="Get notified when a scan completes, fails, or a target's policy compliance drops. Coming soon."
        />
      </div>
    </div>
  );
}
