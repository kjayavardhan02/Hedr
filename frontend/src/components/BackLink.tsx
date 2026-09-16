import Link from "next/link";

export function BackLink({
  href = "/policies",
  label = "Back to Policies",
}: {
  href?: string;
  label?: string;
}) {
  return (
    <Link href={href} className="back-link">
      <span aria-hidden="true">←</span> {label}
    </Link>
  );
}
