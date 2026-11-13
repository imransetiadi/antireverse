// Agents loaded by module specifier in the assessInWorker tests. Not a test file.
import type { AdversaryAgent } from "../../src/types.ts";

/** Blocks its thread forever: only terminating the worker ends it. */
export const blocking: AdversaryAgent = {
  name: "blocking",
  version: "1.0.0",
  model: "test-model",
  async run() {
    for (;;) {
      // spin
    }
  },
};

/** A factory export: called once to make the agent. */
export function makeSubmitter(): AdversaryAgent {
  return {
    name: "submitter",
    version: "1.0.0",
    model: "test-model",
    async run(_context, toolbelt) {
      await toolbelt.submit("W2", { values: ["ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE"] });
    },
  };
}

export default makeSubmitter;
