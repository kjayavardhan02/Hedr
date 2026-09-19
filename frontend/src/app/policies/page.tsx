"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { PolicyCardSkeleton } from "@/components/Skeleton";

export default function PoliciesPage() {
  const router = useRouter();
  const toast = useToast();
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  function load() {
    setLoading(true);
    api
      .listPolicies()
      .then(setPolicies)
      .catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load policies."))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  function requestDelete(id: string) {
    if (confirmingId === id) {
      if (confirmTimer.current) clearTimeout(confirmTimer.current);
      setConfirmingId(null);
      void performDelete(id);
      return;
    }
    setConfirmingId(id);
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    confirmTimer.current = setTimeout(() => setConfirmingId(null), 3000);
  }

  async function performDelete(id: string) {
    const target = policies.find((p) => p.id === id);
    setDeletingId(id);
    try {
      await api.deletePolicy(id);
      toast.show(`Deleted "${target?.name ?? "policy"}".`, "success");
      load();
    } catch (e) {
      toast.show(e instanceof ApiError ? e.message : "Failed to delete policy.", "error");
    } finally {
      setDeletingId(null);
    }
  }

  const baselines = policies.filter((p) => p.is_baseline);
  const custom = policies.filter((p) => !p.is_baseline);

  return (
    <div className="container">
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 12,
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 20,
        }}
      >
        <div>
          <h1 style={{ fontSize: 24, marginBottom: 4 }}>Policies</h1>
          <p className="field-hint">
            Define what &quot;compliant&quot; means for your application, then scan against it.
          </p>
        </div>
        <button className="btn" onClick={() => router.push("/policies/new")}>
          + New Policy
        </button>
      </div>

      {error && <div className="error-box">{error}</div>}
      {loading && (
        <div className="panel">
          <PolicyCardSkeleton />
          <PolicyCardSkeleton />
          <PolicyCardSkeleton />
        </div>
      )}

      {!loading && (
        <>
          <div className="panel fade-in-up">
            <h3 style={{ marginTop: 0, fontSize: 16 }}>Your policies</h3>
            {custom.length === 0 ? (
              <p className="empty-state">
                You haven&apos;t created any policies yet. Start from a baseline below,
                or create one from scratch.
              </p>
            ) : (
              custom.map((p) => (
                <div className="policy-card" key={p.id}>
                  <div className="policy-card-info">
                    <div style={{ fontWeight: 600 }}>
                      {p.name}
                      <span className="pill">v{p.version}</span>
                    </div>
                    <div className="policy-card-meta">
                      {p.headers.length} header rule{p.headers.length === 1 ? "" : "s"}
                      {p.description ? ` — ${p.description}` : ""}
                    </div>
                  </div>
                  <div className="row policy-card-actions">
                    <Link className="btn btn-secondary btn-sm" href={`/policies/${p.id}`}>
                      Edit
                    </Link>
                    <button
                      className={`btn btn-sm ${confirmingId === p.id ? "btn-danger-solid" : "btn-danger"}`}
                      onClick={() => requestDelete(p.id)}
                      disabled={deletingId === p.id}
                    >
                      {deletingId === p.id
                        ? "Deleting…"
                        : confirmingId === p.id
                          ? "Click to confirm"
                          : "Delete"}
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>

          <div className="panel fade-in-up" style={{ animationDelay: "60ms" }}>
            <h3 style={{ marginTop: 0, fontSize: 16 }}>Built-in baselines</h3>
            <p className="field-hint" style={{ marginBottom: 14 }}>
              Baselines are read-only. Use one as a template to create your own
              customizable copy.
            </p>
            {baselines.map((p) => (
              <div className="policy-card" key={p.id}>
                <div className="policy-card-info">
                  <div style={{ fontWeight: 600 }}>
                    {p.name}
                    <span className="pill">baseline</span>
                  </div>
                  <div className="policy-card-meta">
                    {p.headers.length} header rules — {p.description}
                  </div>
                </div>
                <div className="row policy-card-actions">
                  <Link
                    className="btn btn-secondary btn-sm"
                    href={`/policies/new?template=${p.id}`}
                  >
                    Use as template
                  </Link>
                </div>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
