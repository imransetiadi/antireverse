// Agents the API's tests load by module path into prove's assessment worker (assessInWorker). Not a test file.
import type { AdversaryAgent } from "@antireverse/prove";

/** Stops with an error at once: the run ends as `agent_error`. */
export const broken: AdversaryAgent = {
  name: "broken",
  version: "0.0.1",
  model: "test-model",
  run: () => Promise.reject(new Error("broken on purpose")),
};

/** Blocks its thread forever: only terminating the worker ends it. */
export const blocking: AdversaryAgent = {
  name: "blocking",
  version: "0.0.1",
  model: "test-model",
  async run() {
    for (;;) {
      // spin
    }
  },
};
