import Link from "next/link";
import { ShieldLogo } from "@/components/ShieldLogo";

const FEATURES = [
  "Define a policy once — enforce it on every scan",
  "Deterministic pass/fail, always. AI only explains it",
  "Your policies are private to your account",
];

export function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: {
  title: string;
  subtitle: string;
  children: React.ReactNode;
  footer: React.ReactNode;
}) {
  return (
    <div className="auth-shell">
      <div className="auth-visual">
        <span className="auth-blob auth-blob-1" />
        <span className="auth-blob auth-blob-2" />
        <div className="auth-visual-content">
          <Link href="/" className="auth-brand">
            <ShieldLogo size={30} />
            Hedr
          </Link>
          <h2 className="auth-tagline">
            Know exactly what your
            <br />
            security headers actually do.
          </h2>
          <p className="auth-subtagline">
            Define what &quot;compliant&quot; means, scan a live URL or a pasted
            response, and see precisely what passes, what fails, and why.
          </p>
          <ul className="auth-features">
            {FEATURES.map((f) => (
              <li key={f}>
                <svg viewBox="0 0 20 20" fill="none" aria-hidden="true">
                  <circle cx="10" cy="10" r="10" fill="var(--accent)" fillOpacity="0.16" />
                  <path
                    d="M6 10.2l2.4 2.4L14 7"
                    stroke="var(--accent)"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                  />
                </svg>
                {f}
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="auth-form-side">
        <div className="auth-form-card fade-in-up">
          <h1 className="auth-title">{title}</h1>
          <p className="auth-subtitle">{subtitle}</p>
          {children}
        </div>
        <div className="auth-footer">{footer}</div>
      </div>
    </div>
  );
}
