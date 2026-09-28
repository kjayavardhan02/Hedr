import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ToastProvider } from "@/components/Toast";
import { Sidebar } from "@/components/Sidebar";
import { AuthGate } from "@/components/AuthGate";
import { AuthProvider } from "@/lib/auth-context";
import { THEME_INIT_SCRIPT } from "@/lib/theme";
import "./globals.css";

const inter = Inter({ subsets: ["latin"], variable: "--font-inter" });

export const metadata: Metadata = {
  title: "Hedr — HTTP Security Header Policy Analyzer",
  description:
    "Define a security header policy, scan a URL or pasted response, and see exactly what complies and what doesn't.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={inter.variable} suppressHydrationWarning>
      {/* suppressHydrationWarning is scoped to this element only (React
          doesn't propagate it to children) - it exists because the theme
          script below deliberately sets data-theme on <html> before React
          hydrates, which would otherwise be flagged as a mismatch. This is
          the same fix Next.js's own dark-mode guide and the next-themes
          library use for exactly this pattern. */}
      <head>
        {/* Sets data-theme before first paint, from last time's localStorage
            choice - otherwise every load would flash dark (the default)
            even for someone who picked Light. See lib/theme.ts. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <div className="ambient-glow" aria-hidden="true">
          <span className="ambient-blob ambient-blob-1" />
          <span className="ambient-blob ambient-blob-2" />
        </div>
        <ToastProvider>
          <AuthProvider>
            <div className="app-shell">
              <Sidebar />
              <main className="app-content">
                <AuthGate>{children}</AuthGate>
              </main>
            </div>
          </AuthProvider>
        </ToastProvider>
      </body>
    </html>
  );
}
