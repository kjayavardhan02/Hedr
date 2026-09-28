"use client";

import { useEffect, useState } from "react";
import { Avatar } from "@/components/Avatar";
import { AccountSecurityCard } from "@/components/profile/AccountSecurityCard";
import { ComingSoonCard } from "@/components/profile/ComingSoonCard";
import { IconBell, IconCalendar, IconKey } from "@/components/profile/icons";
import { PersonalInformationCard } from "@/components/profile/PersonalInformationCard";
import { PreferencesCard } from "@/components/profile/PreferencesCard";
import { PolicyFormSkeleton } from "@/components/Skeleton";
import { useAuth } from "@/lib/auth-context";
import { api, ApiError } from "@/lib/api";
import { capitalize, formatMonthYear } from "@/lib/format";
import type { DashboardSummary, Profile } from "@/lib/types";

export default function ProfilePage() {
  const { refreshUser } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [editSignal, setEditSignal] = useState(0);

  function load() {
    api
      .getProfile()
      .then(setProfile)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Couldn't load your profile."));
  }

  useEffect(load, []);
  // Non-essential (just powers the two stat tiles on the overview card) -
  // a failure here shouldn't block the rest of the page.
  useEffect(() => {
    api.getDashboardSummary().then(setSummary).catch(() => {});
  }, []);

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
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>Profile</h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Your account, security and preferences - separate from scans, policies and reports.
      </p>

      <div className="panel fade-in-up profile-overview">
        <div className="profile-avatar-ring">
          <Avatar userId={profile.id} firstName={profile.first_name} lastName={profile.last_name} size={84} />
        </div>
        <div className="profile-overview-name">
          {capitalize(profile.first_name)} {capitalize(profile.last_name)}
        </div>
        <div className="field-hint">{profile.email}</div>
        <div className="profile-member-pill">
          <IconCalendar />
          Member since {formatMonthYear(profile.created_at)}
        </div>

        {summary && (
          <div className="profile-stats">
            <div className="profile-stat">
              <div className="profile-stat-value">{summary.reports.total}</div>
              <div className="profile-stat-label">Reports</div>
            </div>
            <div className="profile-stat">
              <div className="profile-stat-value">{summary.policies.total}</div>
              <div className="profile-stat-label">Policies</div>
            </div>
            <div className="profile-stat">
              <div className="profile-stat-value">{summary.average_score ?? "—"}</div>
              <div className="profile-stat-label">Avg. Score</div>
            </div>
          </div>
        )}

        <button
          type="button"
          className="btn btn-secondary btn-sm"
          style={{ marginTop: 20 }}
          onClick={() => setEditSignal((n) => n + 1)}
        >
          Edit Profile
        </button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 16, marginTop: 16 }}>
        <PersonalInformationCard
          profile={profile}
          onUpdated={handleProfileUpdated}
          editSignal={editSignal}
          style={{ animationDelay: "40ms" }}
        />
        <AccountSecurityCard
          profile={profile}
          onPasswordChanged={handlePasswordChanged}
          style={{ animationDelay: "80ms" }}
        />
        <ComingSoonCard
          id="api-keys"
          title="API Keys"
          icon={<IconKey />}
          description="Use API keys to integrate Hedr with CI/CD pipelines and other tools. Coming soon."
          style={{ animationDelay: "120ms" }}
        />
        <PreferencesCard
          defaultPolicyId={profile.default_policy_id}
          style={{ animationDelay: "160ms" }}
        />
        <ComingSoonCard
          id="notifications"
          title="Notifications"
          icon={<IconBell />}
          description="Get notified when a scan completes, fails, or a target's policy compliance drops. Coming soon."
          style={{ animationDelay: "200ms" }}
        />
      </div>
    </div>
  );
}
