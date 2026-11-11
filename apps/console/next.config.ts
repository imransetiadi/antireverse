import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // create-next-app generated `cacheComponents: true` and `partialPrefetching: true` here. Both are
  // deliberately off: with them a page-level redirect() is not a real 307 and show-once key state lingers.
  // `next dev` would otherwise re-create apps/console/AGENTS.md. The version-matched Next.js documentation
  // is at <repository root>/node_modules/next/dist/docs.
  agentRules: false,
  // `next dev` allows one server per build directory. The browser e2e sets AR_NEXT_DIST_DIR (a folder inside
  // .next) so it can run its own Console while a developer's dev server runs here. Unset in normal use.
  distDir: process.env.AR_NEXT_DIST_DIR || ".next",
  turbopack: {
    rules: {
      // Tailwind is wired through this loader (not PostCSS). Keep its version in step with tailwindcss.
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
