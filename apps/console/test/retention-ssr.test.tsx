// @vitest-environment node
import { renderToString } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import { RETENTION } from "./helpers/retention.ts";

// Review 18c, M1: without JavaScript (or before hydration) a shorter period posted by the main form comes back as
// `{ ok: false, confirm }`; the server render must show the confirmation step, not nothing.
vi.mock("react", async (original) => ({
  ...(await original<typeof import("react")>()),
  useActionState: () => [{ ok: false, errors: [], confirm: 7 }, vi.fn(), false],
}));
vi.mock("@/app/actions.ts", () => ({ updateRetentionAction: vi.fn() }));

import { RetentionSettings } from "@/features/data-controls/retention-settings.tsx";

describe("RetentionSettings without JavaScript", () => {
  it("renders the confirmation step the action state asks for", () => {
    const html = renderToString(
      <RetentionSettings retention={{ ...RETENTION, event_retention_days: 30 }} lastRun={null} />,
    );
    expect(html).toContain('data-testid="retention-confirm"');
    expect(html).toContain("Shorten the Event retention to 7 days?");
    expect(html).toContain('name="confirm" value="shorten"');
  });
});
