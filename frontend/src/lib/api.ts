import type {
  ApiErrorBody,
  BurpAnalyzeRequestPayload,
  BurpImportDetail,
  BurpImportListItem,
  BurpImportSummary,
  ComparisonResponse,
  DashboardSummary,
  ExplainRequestPayload,
  ExplainResponse,
  LoginPayload,
  LoginResult,
  MFACodeIssued,
  MFALoginChallenge,
  MFAStatus,
  PasswordChangePayload,
  Policy,
  PolicyCreatePayload,
  Preferences,
  PreferencesUpdatePayload,
  Profile,
  ProfileUpdatePayload,
  RegisterPayload,
  ScanReport,
  ScanReportSummary,
  ScanRequestPayload,
  ScanResult,
  TargetHistoryResponse,
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
  // A FormData body (file upload) must NOT get a manual Content-Type - the
  // browser sets one itself, including the multipart boundary fetch computes
  // from the body. Setting "application/json" here would break the upload.
  const isFormData = init?.body instanceof FormData;
  const res = await fetch(path, {
    ...init,
    headers: {
      ...(isFormData ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers ?? {}),
    },
  });

  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = (await res.json()) as ApiErrorBody;
      if (typeof body?.detail === "string") message = body.detail;
      else if (Array.isArray(body?.detail)) {
        // Schema-validation errors arrive as a list of {msg}; show just the text.
        message = body.detail
          .map((d) => (d.msg ?? "").replace(/^Value error, /, ""))
          .filter(Boolean)
          .join(" ") || message;
      }
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

/** Same error handling as request(), but for an endpoint that returns a
 * binary file rather than JSON - the filename comes from the server's
 * Content-Disposition header, not guessed client-side. */
async function downloadFile(path: string): Promise<{ blob: Blob; filename: string }> {
  const res = await fetch(path);

  if (!res.ok) {
    let message = res.statusText;
    try {
      const body = (await res.json()) as ApiErrorBody;
      if (typeof body?.detail === "string") message = body.detail;
    } catch {
      // ignore - body wasn't JSON
    }
    if (res.status === 401 && typeof window !== "undefined") {
      window.dispatchEvent(new Event(AUTH_EVENT));
    }
    throw new ApiError(res.status, message);
  }

  const disposition = res.headers.get("Content-Disposition") ?? "";
  const utf8Match = /filename\*=UTF-8''([^;]+)/.exec(disposition);
  const asciiMatch = /filename="([^"]+)"/.exec(disposition);
  const filename = utf8Match ? decodeURIComponent(utf8Match[1]) : asciiMatch ? asciiMatch[1] : "export.xlsx";
  const blob = await res.blob();
  return { blob, filename };
}

export const api = {
  register: (payload: RegisterPayload) =>
    request<User>("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  login: (payload: LoginPayload) =>
    request<LoginResult>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  mfaLoginVerify: (challengeId: string, code: string) =>
    request<User>("/api/mfa/login/verify", {
      method: "POST",
      body: JSON.stringify({ challenge_id: challengeId, code }),
    }),
  mfaLoginResend: (challengeId: string) =>
    request<MFALoginChallenge>("/api/mfa/login/resend", {
      method: "POST",
      body: JSON.stringify({ challenge_id: challengeId }),
    }),
  mfaStatus: () => request<MFAStatus>("/api/mfa/status"),
  mfaEnableRequest: () => request<MFACodeIssued>("/api/mfa/enable/request", { method: "POST" }),
  mfaEnableVerify: (code: string) =>
    request<MFAStatus>("/api/mfa/enable/verify", { method: "POST", body: JSON.stringify({ code }) }),
  mfaDisableRequest: (password: string) =>
    request<MFACodeIssued>("/api/mfa/disable/request", { method: "POST", body: JSON.stringify({ password }) }),
  mfaDisableVerify: (code: string) =>
    request<MFAStatus>("/api/mfa/disable/verify", { method: "POST", body: JSON.stringify({ code }) }),
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
  exportReports: (ids: string[]) =>
    request<ScanReport[]>("/api/reports/export", { method: "POST", body: JSON.stringify({ ids }) }),
  getReportComparison: (id: string) => request<ComparisonResponse>(`/api/reports/${id}/comparison`),
  getReportHistory: (id: string) => request<TargetHistoryResponse>(`/api/reports/${id}/history`),
  deleteReport: (id: string) => request<void>(`/api/reports/${id}`, { method: "DELETE" }),
  getDashboardSummary: () => request<DashboardSummary>("/api/dashboard/summary"),
  getProfile: () => request<Profile>("/api/profile"),
  updateProfile: (payload: ProfileUpdatePayload) =>
    request<Profile>("/api/profile", { method: "PATCH", body: JSON.stringify(payload) }),
  changePassword: (payload: PasswordChangePayload) =>
    request<void>("/api/profile/password/change", { method: "POST", body: JSON.stringify(payload) }),
  getPreferences: () => request<Preferences>("/api/profile/preferences"),
  updatePreferences: (payload: PreferencesUpdatePayload) =>
    request<Preferences>("/api/profile/preferences", { method: "PATCH", body: JSON.stringify(payload) }),
  importBurpHistory: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return request<BurpImportSummary>("/api/burp/import", { method: "POST", body: formData });
  },
  analyzeBurpImport: (id: string, payload: BurpAnalyzeRequestPayload) =>
    request<BurpImportDetail>(`/api/burp/${id}/analyze`, { method: "POST", body: JSON.stringify(payload) }),
  listBurpImports: () => request<BurpImportListItem[]>("/api/burp"),
  getBurpImport: (id: string) => request<BurpImportDetail>(`/api/burp/${id}`),
  deleteBurpImport: (id: string) => request<void>(`/api/burp/${id}`, { method: "DELETE" }),
  exportBurpXlsx: (id: string) => downloadFile(`/api/burp/${id}/export`),
};
