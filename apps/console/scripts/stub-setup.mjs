// The set-up of each App for the stand-in API (slice 16): when each step was first done, per Environment.
// Shield: the first Event received. Guard: the first Event whose attestation is valid, whatever the verdict.
// Harden: the earliest registered Build. The stored Event list is capped, so first sightings are kept here.

/** @param {string | null} current @param {string} candidate */
const earliest = (current, candidate) => (current === null || candidate < current ? candidate : current);

export function createSetupStore() {
  /** @type {Map<string, string>} "<App id>/<Environment>/<step>" → when it was first done */
  const firsts = new Map();

  /** @param {string} key @param {string} at */
  const see = (key, at) => firsts.set(key, earliest(firsts.get(key) ?? null, at));

  return {
    /** Records an Event as the API ingests it. */
    recordEvent(event) {
      const prefix = `${event.app_id}/${event.environment}`;
      see(`${prefix}/shield`, event.received_at);
      if (event.attestation?.status === "valid") see(`${prefix}/guard`, event.received_at);
    },

    /** The `setup` of the response body for one App Environment, given the App's Builds. */
    setup(appId, environment, builds) {
      let harden = null;
      for (const one of builds) if (one.environment === environment) harden = earliest(harden, one.registered_at);
      const prefix = `${appId}/${environment}`;
      return {
        environment,
        shield: { done_at: firsts.get(`${prefix}/shield`) ?? null },
        guard: { done_at: firsts.get(`${prefix}/guard`) ?? null },
        harden: { done_at: harden },
      };
    },
  };
}
