import type {
  ApiErrorBody,
  ExplainRequestPayload,
  ExplainResponse,
  Policy,
  PolicyCreatePayload,
  ScanRequestPayload,
  ScanResult,
} from "./types";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

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
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const api = {
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
};
