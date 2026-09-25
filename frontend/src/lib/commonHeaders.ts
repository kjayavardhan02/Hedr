// Content-Security-Policy is deliberately not in this list - it's configured
// through its own structured builder (CSPPolicyBuilder), never as a generic
// header expected-value string.
export const COMMON_HEADERS: { name: string; description: string }[] = [
  { name: "Strict-Transport-Security", description: "Forces browsers to use HTTPS" },
  { name: "X-Content-Type-Options", description: "Stops MIME-type sniffing" },
  { name: "X-Frame-Options", description: "Controls whether the page can be framed" },
  { name: "Referrer-Policy", description: "Controls how much referrer information is sent" },
  { name: "Permissions-Policy", description: "Restricts browser features such as camera and location" },
  { name: "Cross-Origin-Opener-Policy", description: "Isolates the page from other origins' windows" },
  { name: "Cross-Origin-Resource-Policy", description: "Controls which origins can load this resource" },
  { name: "Cross-Origin-Embedder-Policy", description: "Requires cross-origin resources to opt in" },
  { name: "X-XSS-Protection", description: "Legacy browser XSS filter (deprecated)" },
  { name: "Cache-Control", description: "Controls how responses are cached" },
  { name: "Access-Control-Allow-Origin", description: "Which origins may read the response (CORS)" },
  { name: "Access-Control-Allow-Credentials", description: "Allows credentialed cross-origin requests" },
];
