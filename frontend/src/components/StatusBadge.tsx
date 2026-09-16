import type { Status } from "@/lib/types";

function StatusIcon({ status }: { status: Status }) {
  const common = { width: 12, height: 12, viewBox: "0 0 16 16", "aria-hidden": true as const };
  switch (status) {
    case "PASS":
      return (
        <svg {...common}>
          <path
            d="M3.5 8.5l2.7 2.7L12.5 4.8"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </svg>
      );
    case "FAIL":
      return (
        <svg {...common}>
          <path
            d="M4 4l8 8M12 4l-8 8"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>
      );
    case "WARNING":
      return (
        <svg {...common}>
          <path
            d="M8 1.5l7 12.5H1L8 1.5Z"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.6"
            strokeLinejoin="round"
          />
          <path d="M8 6.3v3.1" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="8" cy="11.7" r="0.9" fill="currentColor" />
        </svg>
      );
    default:
      return (
        <svg {...common}>
          <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" strokeWidth="1.6" />
          <path d="M8 7.2v4" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          <circle cx="8" cy="4.7" r="0.9" fill="currentColor" />
        </svg>
      );
  }
}

export function StatusBadge({ status }: { status: Status }) {
  return (
    <span className={`badge badge-${status}`}>
      <StatusIcon status={status} />
      {status}
    </span>
  );
}
