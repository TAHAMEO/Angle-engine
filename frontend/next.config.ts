import type { NextConfig } from "next";

/** Development only: forward /api to the FastAPI server. In production Caddy routes /api directly. */
const devApiOrigin = process.env.ANGEL_DEV_API_ORIGIN;

const securityHeaders = [
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()",
  },
  { key: "X-Robots-Tag", value: "noindex, nofollow" },
];

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  // Do not let `next dev` write AGENTS.md / CLAUDE.md into the project.
  agentRules: false,
  reactStrictMode: true,
  turbopack: { root: import.meta.dirname },
  async rewrites() {
    return devApiOrigin ? [{ source: "/api/:path*", destination: `${devApiOrigin}/api/:path*` }] : [];
  },
  async headers() {
    // The API sets its own headers (its report previews must be frameable by this origin).
    return [{ source: "/((?!api/).*)", headers: securityHeaders }];
  },
};

export default nextConfig;
