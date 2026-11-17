"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

/**
 * Reads the page's data again every `seconds` while it is mounted — a Campaign that is queued or running. The router
 * keeps what is typed in the page (the reason of the stop step). Without JavaScript the page carries a meta refresh
 * instead (campaign-detail.tsx).
 */
export function AutoRefresh({ seconds }: { seconds: number }) {
  const router = useRouter();
  useEffect(() => {
    const timer = setInterval(() => router.refresh(), seconds * 1000);
    return () => clearInterval(timer);
  }, [router, seconds]);
  return <span data-testid="campaign-auto-refresh" hidden />;
}
