import type { NextRequest } from "next/server";
import { crossSiteRefusal } from "@/lib/download-guard.ts";
import { expiredOpsCookie } from "@/lib/ops-session.ts";
import { ROUTES } from "@/lib/routes.ts";

// `GET /ops/expired` (slice 18d): where `/ops` sends an operator whose token the API no longer accepts. A page cannot
// delete a cookie while it renders; this handler clears the operator cookie and opens operator sign-in, which says why
// (Jev, route_handler, 0.93). A request another site made is refused and clears nothing.
export function GET(request: NextRequest): Response {
  const refused = crossSiteRefusal(request);
  if (refused !== null) return refused;
  return new Response(null, {
    status: 303,
    headers: { location: ROUTES.opsSignInExpired, "set-cookie": expiredOpsCookie(), "cache-control": "no-store" },
  });
}
