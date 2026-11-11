import type { Profile } from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

const LABEL: Record<Profile, MessageKey> = {
  light: "build.profile.light",
  balanced: "build.profile.balanced",
  maximum: "build.profile.maximum",
};

/** The protection profile a Build was made with, as a mono tag. The word carries the meaning. */
export function ProfileTag({ profile }: { profile: Profile }) {
  return (
    <span
      data-testid="build-profile"
      data-profile={profile}
      className="inline-flex h-6 items-center rounded-control border border-border-strong px-2 caption-1 text-fg-muted"
    >
      {t(LABEL[profile])}
    </span>
  );
}
