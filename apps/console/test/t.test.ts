// @vitest-environment node
import { describe, expect, it } from "vitest";
import { en } from "@/lib/messages/en.ts";
import { type MessageKey, t } from "@/lib/t.ts";

// The copy table of contract C6, verbatim.
const COPY: Array<[string, string]> = [
  ["onboarding.title", "Create your organization"],
  ["onboarding.name", "Organization name"],
  ["onboarding.submit", "Create organization"],
  ["key.admin.title", "Admin key — shown once"],
  ["key.admin.help", "Save this key now. You sign in with it until user accounts arrive."],
  ["signin.title", "Sign in with an admin key"],
  ["signin.submit", "Sign in"],
  ["signin.invalid", "That key was not accepted."],
  ["apps.title", "Apps"],
  ["apps.empty", "No Apps yet. Create one to get a Shield key."],
  ["apps.new", "New App"],
  ["app.name", "App name"],
  ["app.environment", "Environment"],
  ["app.create", "Create App"],
  ["key.shield.title", "Shield key — shown once"],
  ["shield.monitor", "Shield starts in monitor mode — it observes and cannot block anything yet."],
  ["live.title", "Live"],
  ["live.waiting", "Waiting for the first event from {app}…"],
  ["live.state.live", "Live"],
  ["live.state.reconnecting", "Reconnecting"],
  ["live.state.connecting", "Connecting"],
  ["live.col.time", "Time"],
  ["live.col.decision", "Decision"],
  ["live.col.method", "Method"],
  ["live.col.route", "Route"],
  ["live.col.status", "Status"],
  ["live.col.latency", "Latency"],
  ["live.col.network", "Network"],
  ["decision.allow", "Allowed"],
  ["mode.monitor", "Monitor"],
  ["session.signout", "Sign out"],
  ["copy", "Copy"],
  ["copied", "Copied"],
];

// The copy keys of contract P4 (slice 02), verbatim.
const POLICY_COPY: Array<[string, string]> = [
  ["policy.title", "Policy"],
  ["policy.version", "Version {version}"],
  ["policy.none", "No Rules yet. Shield observes every request and blocks nothing."],
  ["policy.rule.name", "Rule name"],
  ["policy.rule.path", "Path pattern"],
  ["policy.rule.path.help", "For example /api/admin/** — * is one segment, ** is everything below."],
  ["policy.rule.methods", "Methods"],
  ["policy.rule.methods.all", "All methods"],
  ["policy.rule.add", "Add Rule"],
  ["policy.rule.promote", "Promote to enforce"],
  ["policy.rule.demote", "Back to monitor"],
  ["policy.rule.remove", "Remove"],
  ["policy.confirm.promote", "Promote to enforce in {environment}? Requests matching {path} will be blocked."],
  ["policy.confirm.rollback", "Roll back {environment} to the Rules of version {version}?"],
  ["policy.history", "History"],
  ["policy.rollback", "Roll back"],
  ["policy.applied", "Shields apply a new version within 15 seconds."],
  ["policy.key.title", "Policy public key"],
  ["policy.key.help", "Shield accepts only Policies signed with this key."],
  ["policy.guardrail", "A Rule that blocks every request cannot be enforced."],
  [
    "error.policy.stale",
    "This Policy changed while you were editing it, so nothing was saved. Reload the page and try again.",
  ],
  [
    "policy.confirm.broad",
    "This pattern matches most of the App's requests. Enforcing it can take the App offline for its users.",
  ],
  [
    "policy.confirm.broad.rollback",
    "This version enforces a pattern that matches most of the App's requests. Rolling back can take the App offline for its users.",
  ],
  ["policy.confirm.typed", "Type {environment} to confirm"],
  ["policy.confirm.typed.mismatch", "Nothing was published. Type {environment} exactly as shown to confirm."],
  [
    "policy.broad.unconfirmed",
    "This pattern matches most of the App's requests and needs the stronger confirmation. Nothing was published. Reload the page and confirm again.",
  ],
  ["nav.live", "Live"],
  ["nav.policy", "Policy"],
];

// The copy keys of contract P4 (slice 05 — Builds), verbatim.
const BUILD_COPY: Array<[string, string]> = [
  ["nav.builds", "Builds"],
  ["builds.title", "Builds"],
  ["builds.empty", "No Builds yet. Run harden with --register to add one."],
  ["builds.caption", "Builds of {app}, newest first"],
  ["builds.for", "Build {version}"],
  ["apps.col.builds", "Builds"],
  ["apps.builds.for", "Builds of {app}"],
  ["build.col.version", "Version"],
  ["build.col.profile", "Profile"],
  ["build.col.equivalence", "Equivalence"],
  ["build.col.size", "Size"],
  ["build.col.run", "Run"],
  ["build.col.created", "Created"],
  ["build.col.path", "Path"],
  ["build.col.bytes", "Bytes"],
  ["build.col.hash", "SHA-256"],
  ["build.id", "Build ID"],
  ["build.registered", "Registered"],
  ["build.profile", "Profile"],
  ["build.profile.light", "light"],
  ["build.profile.balanced", "balanced"],
  ["build.profile.maximum", "maximum"],
  ["build.equivalence", "Equivalence"],
  ["build.equivalence.passed", "Passed"],
  ["build.equivalence.skipped", "Skipped"],
  ["build.cost.title", "Cost"],
  ["build.cost.size", "Size overhead"],
  ["build.cost.run", "Run overhead"],
  ["build.cost.budget", "Budget {budget} %"],
  ["build.cost.overBudget", "Over budget"],
  ["build.cost.none", "—"],
  ["build.transform.title", "Transform"],
  ["build.transform.mangled", "Local names mangled"],
  ["build.transform.strings", "Strings encrypted"],
  ["build.transform.mangleOnly", "Files with mangling only"],
  ["build.transform.integrity", "Integrity check"],
  ["build.transform.on", "On"],
  ["build.transform.off", "Off"],
  ["build.artifacts", "Artifacts"],
];

// The copy keys of contract P3 (slice 06 — Incidents and alert channels), verbatim.
const INCIDENT_COPY: Array<[string, string]> = [
  ["nav.incidents", "Incidents"],
  ["nav.settings", "Settings"],
  ["nav.alerts", "Alerts"],
  ["severity.critical", "Critical"],
  ["severity.high", "High"],
  ["severity.medium", "Medium"],
  ["severity.low", "Low"],
  ["severity.info", "Info"],
  ["incident.status.open", "Open"],
  ["incident.status.acknowledged", "Acknowledged"],
  ["incident.status.resolved", "Resolved"],
  ["incidents.title", "Incidents"],
  ["incidents.filter", "Filter by status"],
  ["incidents.filter.all", "All"],
  [
    "incidents.empty",
    "No Incidents yet. An Incident opens when a managed detection rule sees a burst of blocked requests or failed sign in attempts from one network.",
  ],
  ["incidents.empty.action", "Set up alert channels"],
  ["incidents.empty.filtered", "No Incidents with the status {status}."],
  ["incidents.filter.clear", "Show all Incidents"],
  ["incidents.col.severity", "Severity"],
  ["incidents.col.title", "Incident"],
  ["incidents.col.app", "App"],
  ["incidents.col.status", "Status"],
  ["incidents.col.lastSeen", "Last seen"],
  ["incident.acknowledge", "Acknowledge"],
  ["incident.resolve", "Resolve"],
  [
    "incident.confirm.resolve",
    "Resolve {title} on {app} ({environment})? A later burst from {network} will open a new Incident.",
  ],
  ["incident.confirm.note", "A resolved Incident is never reopened."],
  ["incident.confirm.required", "Nothing was changed. Confirm the change first."],
  ["incident.resolved.note", "This Incident is resolved. A later burst from the same network opens a new one."],
  ["incident.timeline", "Timeline"],
  ["incident.detection.at", "Detected {time} UTC"],
  ["incident.detection.window", "{count} matching Events between {start} and {end} UTC"],
  ["incident.evidence", "Evidence"],
  ["incident.evidence.none", "No stored Events from this network in the Incident's time span."],
  [
    "error.incident.stale",
    "This Incident changed since the page was loaded, so nothing was saved. Reload the page and try again.",
  ],
  ["alerts.title", "Alert channels"],
  ["alerts.kind.webhook", "Webhook"],
  ["alerts.kind.slack", "Slack"],
  ["alerts.empty", "No alert channels yet. Add a webhook or a Slack channel to be told when an Incident opens."],
  ["alerts.destination", "{host}…{lastFour}"],
  ["alerts.add.title", "Add a channel"],
  ["alerts.add.kind", "Kind"],
  ["alerts.add.name", "Channel name"],
  ["alerts.add.url", "URL"],
  ["alerts.add.submit", "Add channel"],
  ["alerts.added", "{name} was added"],
  ["alerts.secret.title", "Signing secret — shown once"],
  ["alerts.test", "Send test"],
  ["alerts.test.delivered", "Delivered"],
  ["alerts.test.failed.status", "Failed — status {status}"],
  ["alerts.test.failed.none", "Failed — no response"],
  ["alerts.remove", "Remove"],
  ["alerts.confirm.remove", "Remove the alert channel {name}? New Incidents will no longer be sent to {destination}."],
  ["alerts.confirm.required", "Nothing was removed. Confirm the change first."],
  ["error.alerts.kind", "Choose Webhook or Slack."],
  ["error.alerts.url.required", "Enter a URL."],
  ["error.alerts.url.long", "Use 2,048 characters or fewer."],
  ["error.alerts.url.invalid", "Enter a full URL, for example https://hooks.example.com/alerts."],
  ["error.alerts.url.refused", "This address cannot receive alerts. Use an https:// URL on a public host."],
  ["error.alerts.max", "An organization holds at most 10 alert channels. Remove one before adding another."],
];

// The copy keys of contract P5 (slice 07 — leak scan and Canaries), verbatim.
const CANARY_COPY: Array<[string, string]> = [
  ["build.col.canaries", "Canaries"],
  ["build.markers", "Markers"],
  ["build.leakScan", "Leak scan"],
  ["build.leakScan.clean", "Clean"],
  ["build.leakScan.suppressed", "Clean · {count} suppressed"],
  ["build.leakScan.none", "Not scanned"],
  ["build.canaries", "Canaries"],
  ["build.canaries.count.one", "1 Canary"],
  ["build.canaries.count", "{count} Canaries"],
  ["build.canaries.caption", "Canaries planted in Build {version}"],
  ["build.canaries.col.kind", "Kind"],
  ["build.canaries.col.id", "Canary ID"],
  [
    "build.canaries.empty",
    "No Canaries in this Build. Harden plants them in Builds registered with a version that supports Canaries.",
  ],
  ["canary.kind.key", "Decoy key"],
  ["canary.kind.route", "Decoy route"],
  ["incident.fact.canary", "Canary"],
  ["incident.fact.build", "Build"],
];

// The copy keys of contract P4 (slice 10 — Clone Beacon on the Build, clone Incidents), verbatim.
const CLONE_COPY: Array<[string, string]> = [
  ["build.beacon", "Clone Beacon"],
  ["build.beacon.on", "On · {count} origins"],
  ["build.beacon.on.one", "On · 1 origin"],
  ["build.beacon.off", "Off"],
  ["build.beacon.origins", "Allowed origins"],
  [
    "build.beacon.empty",
    "No Clone Beacon in this Build. Harden plants one when the Build is registered with --origin.",
  ],
  ["incident.fact.origin", "Origin"],
  ["incident.fact.none", "—"],
  ["incident.detection.reporter", "Reporter network"],
  ["incident.detection.reporter.unknown", "Unknown network"],
  ["incident.clone.containment", "Containment does not apply to a clone. Take the copy down at its host."],
  [
    "incident.confirm.resolve.clone",
    "Resolve {title} on {app} ({environment})? A later report from {origin} will open a new Incident.",
  ],
  ["incident.resolved.note.clone", "This Incident is resolved. A later report from the same origin opens a new one."],
  ["containment.noTarget", "Nothing to block: this Incident names no Actor and no network."],
  ["error.containment.notApplicable", "Containment does not apply to this Incident."],
];

// The copy keys of contract P4 (slice 09 — containment and the never-block list), verbatim.
const CONTAINMENT_COPY: Array<[string, string]> = [
  ["nav.containment", "Containment"],
  ["nav.allowlist", "Never block"],
  ["containment.title", "Contain"],
  [
    "containment.scope",
    "Blocks apply to {app} in {environment} only, are enforced by its Shields within 30 seconds and end on their own.",
  ],
  ["containment.actor", "Actor"],
  ["containment.actor.option", "{actor} · {count} requests"],
  ["containment.actor.option.one", "{actor} · 1 request"],
  ["containment.duration", "Duration"],
  ["containment.ttl.900", "15 minutes"],
  ["containment.ttl.3600", "1 hour"],
  ["containment.ttl.86400", "24 hours"],
  ["containment.blockActor", "Block actor"],
  ["containment.blockNetwork", "Block network"],
  ["containment.blocking", "Blocking…"],
  [
    "containment.noActor",
    "No Actors to block: Shield sends Actor identities only when an actor key is configured (AR_ACTOR_KEY). You can still block the network.",
  ],
  [
    "containment.resolved",
    "This Incident is resolved, so it can no longer be contained. Earlier blocks are listed below.",
  ],
  ["containment.confirm.actor", "Blocks 1 Actor ({actor}) in {environment} of {app} for {duration}, until {expiry}."],
  [
    "containment.confirm.network",
    "Blocks every client in {network} in {environment} of {app} for {duration}, until {expiry}.",
  ],
  [
    "containment.confirm.network.warning",
    "This blocks everyone who shares {network}, not only the attacker — an office, a mobile carrier or a proxy may sit behind it.",
  ],
  ["containment.confirm.typed", "Type {network} to confirm"],
  [
    "containment.confirm.note",
    "Shields enforce it within 30 seconds. It ends on its own at expiry, or earlier when you lift it. Addresses on the never block list are never blocked.",
  ],
  ["containment.confirm.required", "Nothing was blocked. Confirm the block first."],
  ["containment.confirm.typed.mismatch", "Nothing was blocked. Type {network} exactly as shown."],
  ["containment.until", "{time} UTC"],
  ["containment.contained", "Contained"],
  ["actors.title", "Actors"],
  [
    "actors.empty",
    "No Actors for this Incident. Shield sends Actor identities only when an actor key is configured (AR_ACTOR_KEY); the key stays on your servers.",
  ],
  ["actors.col.actor", "Actor"],
  ["actors.col.requests", "Requests"],
  ["actors.full", "Actor {actor}"],
  ["blocks.title", "Blocks"],
  ["blocks.col.target", "Target"],
  ["blocks.col.status", "Status"],
  ["blocks.col.ends", "Ends"],
  ["blocks.col.createdBy", "Created by"],
  ["blocks.col.actions", "Actions"],
  ["blocks.target.actor", "Actor {actor}"],
  ["blocks.target.network", "Network {network}"],
  ["blocks.status.active", "Active"],
  ["blocks.status.expired", "Expired"],
  ["blocks.status.lifted", "Lifted"],
  ["blocks.ends.active", "Expires {time}"],
  ["blocks.ends.expired", "Expired {time}"],
  ["blocks.ends.lifted", "Lifted {time}"],
  [
    "blocks.empty",
    "No blocks yet. A block created with the bar above is listed here until it ends, and stays on record after.",
  ],
  ["blocks.lift", "Lift"],
  [
    "blocks.confirm.lift.actor",
    "Lift the block of Actor {actor} in {environment} of {app}? Its requests pass again within 30 seconds.",
  ],
  [
    "blocks.confirm.lift.network",
    "Lift the block of {network} in {environment} of {app}? Every client in it passes again within 30 seconds.",
  ],
  ["blocks.confirm.lift.note", "The block stays on record as Lifted, with who lifted it and when."],
  ["blocks.confirm.required", "Nothing was lifted. Confirm the change first."],
  ["appContainment.title", "Containment"],
  ["appContainment.count", "{count} of {max} active blocks"],
  ["appContainment.empty", "No active blocks in {environment}. Blocks are created from an Incident."],
  [
    "incidents.contained.unknown",
    "Blocks could not be loaded, so Incidents are shown without the Contained marker. Reload the page to try again.",
  ],
  ["allowlist.title", "Never block list"],
  ["allowlist.count", "{count} of {max} ranges"],
  ["allowlist.col.cidr", "Range"],
  ["allowlist.col.note", "Note"],
  ["allowlist.col.added", "Added"],
  ["allowlist.col.addedBy", "Added by"],
  ["allowlist.col.actions", "Actions"],
  ["allowlist.note.none", "No note"],
  [
    "allowlist.empty",
    "No ranges yet. Add the networks that must never be blocked, such as your office or your monitoring.",
  ],
  ["allowlist.add.title", "Add a range"],
  ["allowlist.add.cidr", "Range (CIDR)"],
  ["allowlist.add.note", "Note"],
  ["allowlist.add.submit", "Add range"],
  ["allowlist.added", "{cidr} was added"],
  ["allowlist.remove", "Remove"],
  ["allowlist.confirm.remove", "Remove {cidr} from the never block list? Containment blocks can then apply to it."],
  ["allowlist.confirm.required", "Nothing was removed. Confirm the change first."],
  ["error.containment.cap", "This App already has 150 active blocks in {environment}. Lift one first."],
  ["error.containment.overlap", "This network overlaps your never block list."],
  ["error.containment.resolved", "This Incident is resolved, so nothing was blocked."],
  [
    "error.containment.stale",
    "This Incident or its blocks changed since the page was loaded, so nothing was blocked. Reload the page and try again.",
  ],
  [
    "error.containment.ended",
    "This block already ended — it expired or was lifted. Reload the page to see its status.",
  ],
  ["error.allowlist.cidr.required", "Enter a range, for example 203.0.113.0/24."],
  [
    "error.allowlist.cidr.invalid",
    "Enter a range in CIDR form: IPv4 /8 to /32 or IPv6 /16 to /128, for example 203.0.113.0/24.",
  ],
  ["error.allowlist.cidr.canonical", "Write this range as {cidr}: the network address with its host bits zero."],
  ["error.allowlist.note.long", "Use 80 characters or fewer."],
  ["error.allowlist.max", "The never block list holds at most 100 ranges. Remove one before adding another."],
  ["error.allowlist.duplicate", "This range is already on the never block list."],
];

// The copy keys of contract P5 of slice 03 (attestation), verbatim. Trusted is evidence, never proof.
const ATTESTATION_COPY: Array<[string, string]> = [
  ["live.col.client", "Client"],
  [
    "live.client.note",
    "Client shows the Guard attestation Shield verified for each request. It is evidence, not proof.",
  ],
  ["attestation.trusted", "Trusted"],
  ["attestation.suspect", "Suspect"],
  ["attestation.hostile", "Hostile"],
  ["attestation.missing", "No token"],
  ["attestation.invalid", "Invalid"],
  ["attestation.expired", "Expired"],
  ["attestation.unreported", "Not reported"],
  ["attestation.risk", "risk {risk}"],
  [
    "attestation.help.trusted",
    "Shield verified a Guard token that reported no automation signal. This is evidence, not proof of a genuine client.",
  ],
  ["attestation.help.suspect", "Shield verified a Guard token that reported one automation or environment signal."],
  [
    "attestation.help.hostile",
    "Shield verified a Guard token that reported two or more automation or environment signals.",
  ],
  ["attestation.help.missing", "The request carried no Guard token."],
  ["attestation.help.invalid", "The request carried a token that Shield could not verify."],
  ["attestation.help.expired", "The request carried a Guard token that had expired."],
  ["attestation.help.unreported", "This Shield version does not report attestation."],
];

// Contract P5 of slice 04: the Signature column, its chip and the requirement option of a Rule.
const SIGNATURE_COPY: Array<[string, string]> = [
  ["live.col.signature", "Signature"],
  ["signature.signed", "Signed"],
  ["signature.unchecked", "Signed · body not checked"],
  ["signature.missing", "Unsigned"],
  ["signature.invalid", "Invalid"],
  ["signature.mismatch", "Invalid · body changed"],
  ["signature.stale", "Stale"],
  ["signature.replayed", "Replayed"],
  ["signature.unreported", "Not reported"],
  ["signature.help.signed", "Shield verified the signature, and the body matched or there was none."],
  [
    "signature.help.unchecked",
    "Shield verified the signature, but no body check ran. Add shield.verifyBody to your body parser.",
  ],
  ["signature.help.missing", "The request carried no signature."],
  ["signature.help.invalid", "The request carried a signature that Shield could not verify."],
  ["signature.help.mismatch", "The body differed from the one Guard signed. Shield refused it before your handler."],
  ["signature.help.stale", "The signature time was more than 60 seconds away from the time Shield checked it."],
  ["signature.help.replayed", "This Shield saw the same signed request within the last 120 seconds."],
  ["signature.help.unreported", "This Shield version does not report request signatures."],
  ["policy.rule.requires", "Require a signed request"],
  [
    "policy.rule.requires.help",
    "Requests on this route must come from Guard with a valid signature. For routes that take a body, add shield.verifyBody to your body parser.",
  ],
  ["policy.rule.requires.tag", "Signed requests required"],
];

// Slice 19: the Finding screens (Exposure). Pinned so the e2e and the copy review read the same words.
const FINDINGS_COPY: Array<[string, string]> = [
  ["nav.findings", "Findings"],
  ["severity.unknown", "Unknown"],
  ["findings.title", "Findings"],
  [
    "findings.empty",
    "No findings. Airverse checks the packages your builds ship and your servers run against known advisories.",
  ],
  [
    "findings.empty.how",
    "To send components, run antireverse harden with --register next to your lockfile, or start Shield: it reports the packages it runs with once at start.",
  ],
  ["findings.empty.filtered", "No Findings match these filters."],
  ["findings.filter.clear", "Show all Findings"],
  ["findings.filter.severity", "Filter by severity"],
  ["findings.filter.status", "Filter by status"],
  ["findings.filter.source", "Filter by source"],
  ["findings.fix.none", "No fix yet"],
  ["finding.status.open", "Open"],
  ["finding.status.fixed", "Fixed"],
  ["finding.status.ignored", "Ignored"],
  ["finding.source.build", "Build"],
  ["finding.source.runtime", "Running server"],
  ["finding.source.runtime.in", "Running server in {environment}"],
  ["finding.fix.suggestion", "Upgrade to {version} or later"],
  ["finding.affected.all", "All versions"],
  ["finding.ignore", "Ignore"],
  ["finding.ignore.reason", "Reason"],
  ["finding.ignore.until", "Ignore until (UTC)"],
  ["finding.confirm.ignore", "Ignore {advisory} in {package} for {app} ({environment})?"],
  ["finding.reopen", "Reopen"],
  ["error.finding.reason.required", "Enter a reason."],
  ["error.finding.reason.long", "Use 200 characters or fewer."],
  ["error.finding.until", "Choose a date from tomorrow up to 90 days ahead."],
  [
    "error.finding.stale",
    "This Finding changed since the page was loaded, so nothing was saved. Reload the page and try again.",
  ],
  ["finding.confirm.required", "Nothing was changed. Confirm the change first."],
  ["incident.fact.advisory", "Advisory"],
  ["build.findings", "Findings"],
  ["build.components", "Components: {count}"],
  ["build.components.none", "No component list was sent with this Build."],
  ["build.findings.none", "No open Findings in this Build."],
];

describe("message catalog", () => {
  it.each(FINDINGS_COPY)("%s reads exactly as slice 19 pins it", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("fills the Finding strings with the package, the version and the count", () => {
    expect(t("finding.fix.suggestion", { version: "1.2.4" })).toBe("Upgrade to 1.2.4 or later");
    expect(t("findings.aliases.more", { count: 2 })).toBe("+2 more");
    expect(t("build.components", { count: 412 })).toBe("Components: 412");
    expect(
      t("finding.confirm.ignore", {
        advisory: "GHSA-2c3m-4p5q-6r7v",
        package: "example-parser@1.2.3",
        app: "shop-web",
        environment: "production",
      }),
    ).toBe("Ignore GHSA-2c3m-4p5q-6r7v in example-parser@1.2.3 for shop-web (production)?");
  });
  it.each(SIGNATURE_COPY)("%s reads exactly as contract P5 of slice 04 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });
  it.each(ATTESTATION_COPY)("%s reads exactly as contract P5 of slice 03 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });
  it.each(INCIDENT_COPY)("%s reads exactly as contract P3 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("uses the fixed vocabulary for every severity and the Incident statuses", () => {
    expect(["critical", "high", "medium", "low", "info"].map((s) => t(`severity.${s}` as MessageKey))).toEqual([
      "Critical",
      "High",
      "Medium",
      "Low",
      "Info",
    ]);
  });

  it.each(CONTAINMENT_COPY)("%s reads exactly as contract P4 of slice 09 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("states the blast radius and the expiry of a block in one sentence", () => {
    expect(
      t("containment.confirm.actor", {
        actor: "iph_2932b22c…",
        environment: "production",
        app: "shop-web",
        duration: t("containment.ttl.3600"),
        expiry: t("containment.until", { time: "14:05" }),
      }),
    ).toBe("Blocks 1 Actor (iph_2932b22c…) in production of shop-web for 1 hour, until 14:05 UTC.");
    expect(t("error.containment.cap", { environment: "production" })).toBe(
      "This App already has 150 active blocks in production. Lift one first.",
    );
  });

  it.each(CLONE_COPY)("%s reads exactly as contract P4 of slice 10 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("fills the Clone Beacon strings with the count and the origin", () => {
    expect(t("build.beacon.on", { count: 2 })).toBe("On · 2 origins");
    expect(
      t("incident.confirm.resolve.clone", {
        title: "Clone detected",
        app: "shop-web",
        environment: "production",
        origin: "https://clone.example",
      }),
    ).toBe(
      "Resolve Clone detected on shop-web (production)? A later report from https://clone.example will open a new Incident.",
    );
  });

  it.each(CANARY_COPY)("%s reads exactly as contract P5 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("fills the Canary strings with the count and version", () => {
    expect(t("build.leakScan.suppressed", { count: 2 })).toBe("Clean · 2 suppressed");
    expect(t("build.canaries.count", { count: 3 })).toBe("3 Canaries");
    expect(t("build.canaries.caption", { version: "1.5.0" })).toBe("Canaries planted in Build 1.5.0");
  });

  it.each(COPY)("%s reads exactly as the copy table says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it.each(POLICY_COPY)("%s reads exactly as contract P4 says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it.each(BUILD_COPY)("%s reads exactly as the Builds contract says", (key, text) => {
    expect((en as Record<string, string>)[key]).toBe(text);
  });

  it("fills the Build strings with the App, the version and the budget", () => {
    expect(t("builds.caption", { app: "shop-web" })).toBe("Builds of shop-web, newest first");
    expect(t("builds.for", { version: "1.4.0" })).toBe("Build 1.4.0");
    expect(t("build.cost.budget", { budget: 35 })).toBe("Budget 35 %");
  });

  it("fills the Policy confirmations with the Environment and the pattern or version", () => {
    expect(t("policy.version", { version: 12 })).toBe("Version 12");
    expect(t("policy.confirm.promote", { environment: "production", path: "/api/admin/**" })).toBe(
      "Promote to enforce in production? Requests matching /api/admin/** will be blocked.",
    );
    expect(t("policy.confirm.rollback", { environment: "staging", version: 3 })).toBe(
      "Roll back staging to the Rules of version 3?",
    );
  });

  it("has no message that would need a value it is never given: every placeholder is a plain word", () => {
    for (const [key, text] of Object.entries(en)) {
      for (const brace of text.match(/\{[^}]*\}/g) ?? []) expect(`${key}: ${brace}`).toMatch(/: \{[a-zA-Z]+\}$/);
    }
  });

  // Design skill (UIUX.md §3, §10): no hyphenated words in prose. A hyphen stays only inside an identifier —
  // a CLI flag, an HTTP header name, an algorithm name, a date or a placeholder value — matched here by pattern.
  const IDENTIFIER_HYPHEN: readonly RegExp[] = [
    /^--[a-z][a-z-]*$/, // CLI flags: --register, --origin
    /^[A-Z]{2,}-[A-Z][a-z]+$/, // HTTP header names: AR-Signature
    /^[A-Z]{2,}-\d+$/, // algorithm names: SHA-256
    /^\d{4}-\d{2}-\d{2}/, // dates
  ];

  it("has no hyphenated word in its prose; hyphens stay only inside identifiers", () => {
    const offending: string[] = [];
    for (const [key, text] of Object.entries(en)) {
      for (const raw of text.split(/\s+/)) {
        const token = raw.replace(/^[("'“‘]+|[)"'”’.,:;?…]+$/g, "");
        if (!/[\p{L}\d]-[\p{L}\d]/u.test(token) && !token.startsWith("--")) continue;
        if (!IDENTIFIER_HYPHEN.some((pattern) => pattern.test(token))) offending.push(`${key}: ${token}`);
      }
    }
    expect(offending).toEqual([]);
  });

  it("is calm: no exclamation mark and none of the banned filler words", () => {
    const banned =
      /revolutioni[sz]e|supercharge|cutting[ -]edge|effortless|transform your workflow|next level|harness the power|world[ -]class/i;
    for (const [key, text] of Object.entries(en)) {
      expect(`${key}: ${text}`).not.toMatch(/!/);
      expect(`${key}: ${text}`).not.toMatch(banned);
    }
  });

  it("uses the fixed vocabulary for every Decision and rule mode", () => {
    expect(t("decision.monitor")).toBe("Monitored");
    expect(t("decision.challenge")).toBe("Challenged");
    expect(t("decision.throttle")).toBe("Throttled");
    expect(t("decision.block")).toBe("Blocked");
    expect(t("decision.deceive")).toBe("Deceived");
    expect(t("mode.enforce")).toBe("Enforce");
  });
});

describe("t", () => {
  it("returns the catalog text", () => {
    expect(t("apps.title")).toBe("Apps");
  });

  it("substitutes {app}", () => {
    expect(t("live.waiting", { app: "shop-web" })).toBe("Waiting for the first event from shop-web…");
  });

  it("inserts a value literally, even when it looks like a placeholder or a replacement pattern", () => {
    expect(t("live.waiting", { app: "{app} $& $1" })).toBe("Waiting for the first event from {app} $& $1…");
  });

  it("throws on an unknown key", () => {
    expect(() => t("no.such.key" as MessageKey)).toThrow(/no\.such\.key/);
    expect(() => t("toString" as MessageKey)).toThrow(/toString/);
  });

  it("throws when a placeholder has no value", () => {
    expect(() => t("live.waiting")).toThrow(/app/);
  });
});
