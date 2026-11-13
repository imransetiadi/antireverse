// The Policy simulation of the stand-in API (slice 11): plausible, made-up figures in the shape of the protocol's
// `SimulationResultSchema`. Nothing is replayed: the figures are derived from each Rule's pattern, so the same
// Rules give the same figures. Pure and without imports, so that a test can check the shape against the protocol.

const DAY_MS = 24 * 3_600_000;
/** Requests "recorded" without a route template: no Rule can be judged against them. */
const UNMATCHED = 310;
/** Requests from an older Shield that recorded no signature: a signature Rule matches them but cannot judge them. */
const UNSIGNED_UNKNOWN = 15;
const EVENTS_BASE = 18_452;

/** A small stable number from a text. */
function hash(text) {
  let value = 7;
  for (const char of text) value = (value * 31 + char.charCodeAt(0)) % 1_000_003;
  return value;
}

/** Route templates of the requests a Rule would refuse, most first: at most three, none when it refuses nothing. */
function sampleRoutes(rule, refused) {
  const matched = refused;
  if (matched === 0) return [];
  const method = rule.methods?.[0] ?? "GET";
  const template = (path) => path.replace(/\*/g, ":id");
  if (!rule.path.endsWith("/**")) return [{ route: template(rule.path), method, count: matched }];
  const base = template(rule.path.slice(0, -3));
  const routes = [`${base}/:id`, `${base}/export`, base === "" ? "/" : base];
  const counts = [Math.ceil(matched / 2), Math.floor(matched / 3), 0];
  counts[2] = matched - counts[0] - counts[1];
  return routes.map((route, n) => ({ route, method, count: counts[n] })).filter((sample) => sample.count >= 1);
}

/**
 * What `rules` (checked Rules, in Policy order) "would have done" in the 24 hours before `nowMs`.
 * A Rule that is enforced already refused what it matched, so the draft refuses nothing more there.
 */
export function stubSimulation(rules, nowMs = Date.now()) {
  const rows = rules.map((rule, index) => {
    const seed = hash(`${rule.path} ${(rule.methods ?? []).join(",")}`);
    const matched = 40 + (seed % 900);
    const signature = rule.requires === "signature";
    const throttle = rule.action === "throttle";
    const enforced = rule.mode === "enforce";
    // An enforced block Rule refused everything it matched; an enforced limit or requirement, what was over it.
    const share = signature ? 0.08 : throttle ? 0.3 : 1;
    const hit = Math.max(1, Math.floor(matched * share));
    const already_refused = enforced ? hit : seed % 3;
    const refused = enforced ? 0 : Math.min(hit, matched - already_refused);
    // Requests recorded without a client (a Shield without an actor key): every third Rule has some.
    const unknown = seed % 3 === 0 ? Math.min(refused, 1 + (seed % 40)) : 0;
    const row = {
      index,
      ...(rule.id === undefined ? {} : { id: rule.id }),
      name: rule.name,
      matched,
      would_block: !signature && !throttle ? refused : 0,
      would_fail_signature: signature ? refused : 0,
      would_throttle: throttle ? refused : 0,
      already_refused,
      undecidable: UNMATCHED + (signature ? UNSIGNED_UNKNOWN : 0),
      clients_affected: Math.min(refused - unknown, 1 + (seed % 23)),
      unknown_client_events: unknown,
      sample_routes: sampleRoutes(rule, refused),
    };
    if (enforced) return row;
    // Promoted alone, a Rule in Monitor mode also refuses what an earlier Rule would have taken first.
    return {
      ...row,
      if_promoted: {
        would_refuse: refused + (seed % 9),
        clients_affected: row.clients_affected,
        unknown_client_events: unknown,
        undecidable: row.undecidable,
      },
    };
  });
  const sum = (member) => rows.reduce((total, row) => total + row[member], 0);
  const would_refuse = sum("would_block") + sum("would_fail_signature") + sum("would_throttle");
  return {
    period: { from: new Date(nowMs - DAY_MS).toISOString(), to: new Date(nowMs).toISOString() },
    events: Math.max(EVENTS_BASE, sum("matched") + UNMATCHED),
    ran_at: new Date(nowMs).toISOString(),
    truncated: false,
    undecidable_events:
      rows.length === 0 ? 0 : UNMATCHED + (rows.some((row) => row.would_fail_signature > 0) ? UNSIGNED_UNKNOWN : 0),
    not_simulated: [
      "patches",
      "containments",
      "decoded_paths",
      "device_limits",
      "body_verification",
      "unrecorded_requests",
      "counter_eviction",
      "custom_counter_store",
      "timing",
    ],
    rules: rows,
    totals: {
      would_refuse,
      clients_affected: Math.min(would_refuse - sum("unknown_client_events"), sum("clients_affected")),
      unknown_client_events: sum("unknown_client_events"),
    },
  };
}
