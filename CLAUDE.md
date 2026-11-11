# Anti Reverse — rules for every session and every agent

Read [MEMORY.md](MEMORY.md) first: glossary, decisions, lessons, handoffs. The specification is the seven documents beside it.

## Rule 1 — Always involve Jev in decisions (owner's instruction, 2026-11-10)

Every decision with alternatives goes through Jev before it is made. No exceptions for "obvious" choices.

- **Choices:** call `jev_decide` with the decision, the evidence, the priorities, 2–6 candidates and the requirements that matter. Record Jev's pick, its confidence and any contradicted requirement next to the decision (decision log in MEMORY.md §4, the plan, or the report to the owner).
- **Before claiming done:** call `jev_gate` or `jev_verify` on the completion claims with the evidence (test output, diffs).
- **On a diff:** `jev_review` before declaring a task finished.
- **Who decides:** Jev informs; it does not overrule the owner. Product, scope, cost and risk decisions — and any case where Jev returns `ask_user` or low confidence — go to the owner, with Jev's view stated.
- **Disagreeing with Jev:** allowed, but say so and give the reason.
- **What never goes to Jev:** keys, tokens, passwords, customer or tenant data. Text sent to Jev leaves the machine to its provider.
- **How to reach it:** the MCP server `jev` (tools `mcp__jev__*`) is registered for this folder. If the tools are not loaded in a session, run the server over stdio (`npx -y @jkudish/jev-mcp@0.14.7`) with `TYPESAFE_API_KEY` taken from the `jev` entry of the local Claude Code configuration — never copy the key into a file in this repository.

## Rule 2 — How work is done here

- Design before code; the owner approves the design. Then a ticket in `tickets/`, a plan in `plans/`.
- Test first: a failing test, seen failing, then the code.
- Evidence before claims: run the command and read its output before saying something passes.
- Every slice gets an independent review that must reproduce what it reports; fix confirmed findings test-first.
- When the owner says stop: halt workers and the processes they started first, then report.
- English for code, documents and interface text.
