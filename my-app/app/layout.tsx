import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { SiteHeader } from "@/components/site-header";
import "./globals.css";

const geistSans = Geist({ variable: "--font-geist-sans", subsets: ["latin"] });
const geistMono = Geist_Mono({ variable: "--font-geist-mono", subsets: ["latin"] });

export const metadata: Metadata = {
  title: "RepoShield — know what a repo does before you run it",
  description:
    "Paste an unfamiliar GitHub repository and find out what it executes when you install or open it. Built for developers being sent coding assignments they did not ask for.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="flex min-h-full flex-col">
        <SiteHeader />
        <main className="relative z-10 flex-1">{children}</main>
        <footer className="relative z-10 border-t border-[var(--color-border)] py-5">
          <div className="mx-auto max-w-6xl px-5 text-xs text-[var(--color-faint)]">
            Scan results are stored in your browser and never sent to our servers.
            RepoShield reports evidence about what a repository contains — it cannot
            prove that code is safe.
          </div>
        </footer>
      </body>
    </html>
  );
}
