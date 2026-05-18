import type { Metadata } from "next";
import "./globals.css";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Auto-pen",
  description: "LLM-powered automated penetration testing",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ja">
      <body className="min-h-screen bg-gray-50 text-gray-900 dark:bg-gray-950 dark:text-gray-100">
        <header className="border-b border-gray-200 dark:border-gray-800 bg-white dark:bg-gray-900 sticky top-0 z-40">
          <div className="max-w-6xl mx-auto px-4 h-14 flex items-center gap-6">
            <Link href="/" className="font-bold text-lg tracking-tight text-gray-900 dark:text-gray-100">
              🔒 Auto-pen
            </Link>
            <nav className="flex gap-4 text-sm text-gray-600 dark:text-gray-300">
              <Link href="/sessions" className="hover:text-gray-900 dark:hover:text-white transition-colors">Sessions</Link>
              <Link href="/sessions/new" className="hover:text-gray-900 dark:hover:text-white transition-colors">New Scan</Link>
              <Link href="/tools" className="hover:text-gray-900 dark:hover:text-white transition-colors">Tools</Link>
            </nav>
          </div>
        </header>
        <main className="max-w-6xl mx-auto px-4 py-6">{children}</main>
      </body>
    </html>
  );
}
