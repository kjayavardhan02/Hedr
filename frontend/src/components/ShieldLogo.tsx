export function ShieldLogo({ size = 20 }: { size?: number }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <path
        d="M12 2.5 4.5 5.3v5.4c0 5 3.2 8.8 7.5 10.8 4.3-2 7.5-5.8 7.5-10.8V5.3L12 2.5Z"
        fill="var(--accent)"
        opacity="0.18"
      />
      <path
        d="M12 2.5 4.5 5.3v5.4c0 5 3.2 8.8 7.5 10.8 4.3-2 7.5-5.8 7.5-10.8V5.3L12 2.5Z"
        stroke="var(--accent)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M8.7 12.1l2.2 2.2 4.4-4.6"
        stroke="var(--accent)"
        strokeWidth="1.6"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}
