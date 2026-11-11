import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { t } from "@/lib/t.ts";
import "./globals.css";

// UIUX.md §4.3: Geist for the interface, Geist Mono only where monospace is needed (identifiers, code, data).
// next/font self-hosts both. Upright only, nothing bolder than 600 is used.
const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
  weight: ["400", "500", "600"],
  style: "normal",
  display: "swap",
});
const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
  weight: ["400"],
  style: "normal",
  display: "swap",
});

export const metadata: Metadata = { title: t("meta.title") };

// No Suspense boundary and no loading.tsx anywhere above the pages: a session guard must be able to
// answer with a real 307.
export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}>
      <body className="flex min-h-full flex-col bg-bg font-sans text-fg">
        <a
          href="#content"
          className="sr-only rounded-control bg-surface-raised px-3 py-2 button-md focus:not-sr-only focus:absolute focus:start-2 focus:top-2 focus:z-60"
        >
          {t("nav.skip")}
        </a>
        {children}
      </body>
    </html>
  );
}
