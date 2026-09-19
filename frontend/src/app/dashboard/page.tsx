"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { api, ApiError } from "@/lib/api";
import { useAuth } from "@/lib/auth-context";
import { capitalize } from "@/lib/format";
import type { Policy } from "@/lib/types";
import { PolicyCardSkeleton } from "@/components/Skeleton";

export default function DashboardPage() {
  const { user } = useAuth();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .listPolicies()
      .then(setPolicies)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load policies."))
      .finally(() => setLoading(false));
  }, []);

  const custom = policies.filter((p) => !p.is_baseline);
  const baselines = policies.filter((p) => p.is_baseline);

  return (
    <div className="container">
      <h1 style={{ fontSize: 24, marginBottom: 4 }}>
        Welcome back, {user?.first_name && capitalize(user.first_name)}
      </h1>
      <p className="field-hint" style={{ marginBottom: 20 }}>
        Here&apos;s a quick overview of your account.
      </p>

      <div className="row" style={{ marginBottom: 20 }}>
        <Link href="/scan" className="btn">
          Scan a target
        </Link>
        <Link href="/policies/new" className="btn btn-secondary">
          + New Policy
        </Link>
      </div>

      {error && <div className="error-box">{error}</div>}

      {loading ? (
        <div className="panel">
          <PolicyCardSkeleton />
          <PolicyCardSkeleton />
        </div>
      ) : (
        <>
          <div className="row" style={{ marginBottom: 16 }}>
            <div className="panel fade-in-up" style={{ flex: "1 1 200px" }}>
              <div className="field-hint">Your policies</div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>{custom.length}</div>
            </div>
            <div className="panel fade-in-up" style={{ flex: "1 1 200px", animationDelay: "40ms" }}>
              <div className="field-hint">Built-in baselines</div>
              <div style={{ fontSize: 28, fontWeight: 700, marginTop: 4 }}>{baselines.length}</div>
            </div>
          </div>

          <div className="panel fade-in-up" style={{ animationDelay: "80ms" }}>
            <h3 style={{ marginTop: 0, fontSize: 16 }}>Your policies</h3>
            {custom.length === 0 ? (
              <p className="empty-state">
                You haven&apos;t created any policies yet.{" "}
                <Link href="/policies/new">Create one</Link> or start from a baseline on the{" "}
                <Link href="/policies">Policies</Link> page.
              </p>
            ) : (
              custom.map((p) => (
                <div className="policy-card" key={p.id}>
                  <div className="policy-card-info">
                    <div style={{ fontWeight: 600 }}>{p.name}</div>
                    <div className="policy-card-meta">
                      {p.headers.length} header rule{p.headers.length === 1 ? "" : "s"}
                    </div>
                  </div>
                  <div className="row policy-card-actions">
                    <Link className="btn btn-secondary btn-sm" href={`/policies/${p.id}`}>
                      Edit
                    </Link>
                  </div>
                </div>
              ))
            )}
          </div>
        </>
      )}
    </div>
  );
}
