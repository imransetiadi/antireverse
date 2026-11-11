"use client";

import { Button } from "@/components/button.tsx";
import { t } from "@/lib/t.ts";

// Shown when a page could not be rendered — in practice, when the Anti Reverse API did not answer.
// The error itself is neither shown nor logged here: Next.js logs it on the server with a digest.
export default function ErrorScreen({ retry }: { error: unknown; retry: () => void }) {
  return (
    <main id="content" className="mx-auto flex w-full max-w-xl flex-1 flex-col gap-4 px-4 py-6">
      <h1 className="heading-2">{t("error.page.title")}</h1>
      <p role="alert" className="text-fg-muted">
        {t("error.page.body")}
      </p>
      <div>
        <Button onClick={() => retry()}>{t("error.page.retry")}</Button>
      </div>
    </main>
  );
}
