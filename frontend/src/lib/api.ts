import type {
  ApiErrorBody,
  ExplainRequestPayload,
  ExplainResponse,
  LoginPayload,
  Policy,
  PolicyCreatePayload,
  RegisterPayload,
  ScanReport,
  ScanReportSummary,
  ScanRequestPayload,
  ScanResult,
  User,
} from "./types";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

// Fired whenever any request comes back 401, so a single AuthProvider can
// clear the current user and redirect to /login without every call site
// needing to special-case it.
export const AUTH_EVENT = "hedr:unauthorized";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = (await res.json()) as ApiErrorBody;
      if (body?.detail) message = body.detail;
    } catch {
      // ignore - body wasn't JSON
    }
    if (res.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new Event(AUTH_EVENT));
    }
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const api = {
  register: (payload: RegisterPayload) =>
    request<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  login: (payload: LoginPayload) =>
    request<User>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  logout: () => request<void>("/api/auth/logout", { method: "POST" }),
  me: () => request<User>("/api/auth/me"),
  listPolicies: () => request<Policy[]>("/api/policies"),
  listBaselines: () => request<Policy[]>("/api/policies/baselines"),
  getPolicy: (id: string) => request<Policy>(`/api/policies/${id}`),
  createPolicy: (payload: PolicyCreatePayload) =>
    request<Policy>("/api/policies", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  updatePolicy: (id: string, payload: PolicyCreatePayload) =>
    request<Policy>(`/api/policies/${id}`, {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  deletePolicy: (id: string) =>
    request<void>(`/api/policies/${id}`, { method: "DELETE" }),
  scan: (payload: ScanRequestPayload) =>
    request<ScanResult>("/api/scan", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  explain: (payload: ExplainRequestPayload) =>
    request<ExplainResponse>("/api/explain", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listReports: () => request<ScanReportSummary[]>("/api/reports"),
  getReport: (id: string) => request<ScanReport>(`/api/reports/${id}`),
  deleteReport: (id: string) => request<void>(`/api/reports/${id}`, { method: "DELETE" }),
};
