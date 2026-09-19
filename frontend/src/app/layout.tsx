import type { Metadata } from "next";
import { Inter } from "next/font/google";
import { ToastProvider } from "@/components/Toast";
import { Sidebar } from "@/components/Sidebar";
import { AuthGate } from "@/components/AuthGate";
import { AuthProvider } from "@/lib/auth-context";
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
    <html lang="en" className={inter.variable}>
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
