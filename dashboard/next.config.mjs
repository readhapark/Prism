/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Public Cloudflare quick tunnels hit the dev server cross-origin.
  allowedDevOrigins: [
    "*.trycloudflare.com",
    "liked-international-fires-read.trycloudflare.com",
  ],
  async rewrites() {
    // Proxy to the local Prism API so the browser can use same-origin
    // requests (avoids cross-tunnel CORS + improves EventSource reliability).
    const api = process.env.PRISM_API_ORIGIN || "http://127.0.0.1:8787";
    return [
      {
        source: "/prism-api/:path*",
        destination: `${api.replace(/\/$/, "")}/:path*`,
      },
    ];
  },
};

export default nextConfig;
