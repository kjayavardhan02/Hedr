"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { api, ApiError } from "@/lib/api";
import type { Policy } from "@/lib/types";
import { useToast } from "@/components/Toast";
import { PolicyCardSkeleton } from "@/components/Skeleton";
import { DateRangeFilter, FilterBar, SearchField, type FilterTab } from "@/components/FilterBar";
import { inDateRange } from "@/lib/filters";
import { Highlight } from "@/components/Highlight";

type PolicyFilterField = "name" | "date" | "type";
type PolicyTypeFilter = "csp" | "headers" | "";

const FILTER_TABS: FilterTab<PolicyFilterField>[] = [
  { field: "name", label: "Name", icon: "policy" },
  { field: "date", label: "Last updated", icon: "date" },
  { field: "type", label: "Type", icon: "type" },
];

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

  const [filterField, setFilterField] = useState<PolicyFilterField>("name");
  const [filterText, setFilterText] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [typeFilter, setTypeFilter] = useState<PolicyTypeFilter>("");
  const filterActive =
    filterField === "date" ? Boolean(dateFrom || dateTo) : filterField === "type" ? typeFilter !== "" : filterText.trim() !== "";

  function clearFilter() {
    setFilterText("");
    setDateFrom("");
    setDateTo("");
    setTypeFilter("");
  }

  // The filter applies to both "Your policies" and the built-in baselines.
  const visiblePolicies = useMemo(() => {
    if (!filterActive) return policies;
    const needle = filterText.trim().toLowerCase();
    return policies.filter((p) => {
      if (filterField === "name") return p.name.toLowerCase().includes(needle);
      if (filterField === "type") return typeFilter === "csp" ? Boolean(p.csp_policy) : !p.csp_policy;
      return inDateRange(p.updated_at, dateFrom, dateTo);
    });
  }, [policies, filterActive, filterField, filterText, typeFilter, dateFrom, dateTo]);

  const nameQuery = filterField === "name" ? filterText : "";
  const baselines = visiblePolicies.filter((p) => p.is_baseline);
  const custom = visiblePolicies.filter((p) => !p.is_baseline);

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

      {!loading && policies.length > 0 && (
        <FilterBar
          tabs={FILTER_TABS}
          active={filterField}
          onTab={(field) => {
            setFilterField(field);
            clearFilter();
          }}
          count={visiblePolicies.length}
          total={policies.length}
          noun="policy"
          pluralNoun="policies"
          filterActive={filterActive}
          onClear={clearFilter}
        >
          {filterField === "type" ? (
            <div className="rf-chips" role="group" aria-label="Policy type">
              {(
                [
                  ["csp", "Includes CSP"],
                  ["headers", "Headers only"],
                ] as const
              ).map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  className={`rf-chip ${typeFilter === value ? "rf-chip-on" : ""}`}
                  aria-pressed={typeFilter === value}
                  onClick={() => setTypeFilter((cur) => (cur === value ? "" : value))}
                >
                  {label}
                </button>
              ))}
              <span className="rf-hint">Whether the policy evaluates Content-Security-Policy</span>
            </div>
          ) : filterField === "date" ? (
            <DateRangeFilter
              from={dateFrom}
              to={dateTo}
              onChange={(from, to) => {
                setDateFrom(from);
                setDateTo(to);
              }}
            />
          ) : (
            <SearchField value={filterText} onChange={setFilterText} placeholder="Search by policy name…" />
          )}
        </FilterBar>
      )}

      {!loading && (
        <>
          <div className="panel fade-in-up">
            <h3 style={{ marginTop: 0, fontSize: 16 }}>Your policies</h3>
            {custom.length === 0 && filterActive ? (
              <p className="empty-state">No policies match this filter.</p>
            ) : custom.length === 0 ? (
              <p className="empty-state">
                You haven&apos;t created any policies yet. Start from a baseline below,
                or create one from scratch.
              </p>
            ) : (
              custom.map((p) => (
                <div className="policy-card" key={p.id}>
                  <div className="policy-card-info">
                    <div style={{ fontWeight: 600 }}>
                      <Highlight text={p.name} query={nameQuery} />
                      <span className="pill">v{p.version}</span>
                    </div>
                    <div className="policy-card-meta">
                      {p.headers.length} header rule{p.headers.length === 1 ? "" : "s"}
                      {p.csp_policy ? " · evaluates CSP" : ""}
                      {p.description ? ` — ${p.description}` : ""}
                    </div>
                  </div>
                  <div className="row policy-card-actions">
                    <Link className="btn btn-secondary btn-sm" href={`/policies/${p.id}`}>
                      Edit
                    </Link>
                    <Link className="btn btn-secondary btn-sm" href={`/policies/new?template=${p.id}`}>
                      Clone
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

          {(!filterActive || baselines.length > 0) && (
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
                      <Highlight text={p.name} query={nameQuery} />
                      <span className="pill">baseline</span>
                    </div>
                    <div className="policy-card-meta">
                      {p.headers.length} header rules
                      {p.csp_policy ? " · evaluates CSP" : ""} — {p.description}
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
          )}
        </>
      )}
    </div>
  );
}
