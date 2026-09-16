import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import { ToastProvider } from "@/components/Toast";
import { ShieldLogo } from "@/components/ShieldLogo";
import { NavLinks } from "@/components/NavLinks";
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
        <ToastProvider>
          <nav className="nav">
            <div className="nav-inner">
              <Link href="/" className="brand">
                <ShieldLogo />
                Hedr
              </Link>
              <NavLinks />
            </div>
          </nav>
          {children}
        </ToastProvider>
      </body>
    </html>
  );
}
