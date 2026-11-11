import type { StoredEvent } from "@antireverse/protocol";

export interface EventBus {
  /** Hands the Event to every subscriber of its Organization and App. Never throws. */
  publish(event: StoredEvent): void;
  /** Returns the function that ends the subscription; calling it more than once is harmless. */
  subscribe(filter: { organizationId: string; appId: string }, onEvent: (event: StoredEvent) => void): () => void;
  /**
   * Receives every Event of every Organization (the Detector). Not a live stream: `count` does not include it.
   * Returns the function that ends the subscription; calling it more than once is harmless.
   */
  subscribeAll(onEvent: (event: StoredEvent) => void): () => void;
  /** Open per-App subscriptions (live streams): of one Organization, or of all when none is given. */
  count(organizationId?: string): number;
}

interface Subscription {
  appId: string;
  onEvent: (event: StoredEvent) => void;
}

/** An in-process fan-out of stored Events to live streams. Subscriptions are kept per Organization. */
export function createEventBus(): EventBus {
  const byOrganization = new Map<string, Set<Subscription>>();
  const everything = new Set<(event: StoredEvent) => void>();

  /** One failing subscriber must not keep the Event from the others, nor fail the ingest request. */
  function deliver(onEvent: (event: StoredEvent) => void, event: StoredEvent): void {
    try {
      onEvent(event);
    } catch {
      // Swallowed: see above.
    }
  }

  return {
    publish(event) {
      // A copy: a subscriber may unsubscribe while the Event is being delivered.
      for (const onEvent of [...everything]) {
        if (everything.has(onEvent)) deliver(onEvent, event);
      }
      const subscriptions = byOrganization.get(event.organization_id);
      if (subscriptions === undefined) return;
      // A copy: a subscriber may unsubscribe while the Event is being delivered.
      for (const subscription of [...subscriptions]) {
        if (subscription.appId !== event.app_id || !subscriptions.has(subscription)) continue;
        deliver(subscription.onEvent, event);
      }
    },

    subscribeAll(onEvent) {
      // A wrapper, so that the same function subscribed twice is two subscriptions.
      const entry = (event: StoredEvent) => onEvent(event);
      everything.add(entry);
      return () => {
        everything.delete(entry);
      };
    },

    subscribe(filter, onEvent) {
      const subscription: Subscription = { appId: filter.appId, onEvent };
      let subscriptions = byOrganization.get(filter.organizationId);
      if (subscriptions === undefined) {
        subscriptions = new Set();
        byOrganization.set(filter.organizationId, subscriptions);
      }
      subscriptions.add(subscription);
      return () => {
        const current = byOrganization.get(filter.organizationId);
        if (current === undefined) return;
        current.delete(subscription);
        if (current.size === 0) byOrganization.delete(filter.organizationId);
      };
    },

    count(organizationId) {
      if (organizationId !== undefined) return byOrganization.get(organizationId)?.size ?? 0;
      let total = 0;
      for (const subscriptions of byOrganization.values()) total += subscriptions.size;
      return total;
    },
  };
}
