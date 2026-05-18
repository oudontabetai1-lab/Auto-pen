import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";

const nextConfig: NextConfig = {
  // Proxy /api/* to the FastAPI backend during development.
  // Set NEXT_PUBLIC_API_URL for non-default hosts.
  //
  // NB: WebSocket routes (/ws/*) are NOT proxied via rewrites — Next.js
  // disallows ws:// destinations. The browser opens the WS directly using
  // NEXT_PUBLIC_WS_URL (configured in src/lib/ws.ts) so it bypasses Next
  // entirely.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_URL}/api/:path*`,
      },
    ];
  },
};

export default nextConfig;
