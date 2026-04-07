import type { NextConfig } from "next";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8080";
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8080";

const nextConfig: NextConfig = {
  // Proxy /api/* and /ws/* to the FastAPI backend during development.
  // In production, set NEXT_PUBLIC_API_URL and NEXT_PUBLIC_WS_URL instead.
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: `${API_URL}/api/:path*`,
      },
      {
        source: "/ws/:path*",
        destination: `${WS_URL}/ws/:path*`,
      },
    ];
  },
};

export default nextConfig;
