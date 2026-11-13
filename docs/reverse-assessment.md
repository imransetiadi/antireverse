# Reverse Assessment

A Reverse Assessment attacks the protected output of a registered Build, on purpose and within a fixed budget, and reports how well it resisted as the **Reverse Resistance Score** (RRS), from 0 to 100. Higher means more resistant.

## Run one

Register the Build with its route inventory and protected functions, and ask for an Assessment:

```bash
npx tsx packages/harden/src/cli.ts harden dist --out dist-protected --integrity \
  --register --endpoint http://127.0.0.1:8787 --key-env AR_ADMIN_KEY \
  --app <appId> --environment production --build-version 1.4.0 \
  --routes routes.json --logic logic.json --assess T1
```

Harden prints the Assessment id and a link to the Build page. There, **Reverse resistance** shows the score or why there is none, each Objective with its evidence and a fix suggestion, and the **History** of Assessments. **Assess again** runs a new Assessment on the uploaded bundle once a run has finished; the bundle is kept for 30 days after the last run.

To fail a CI step on the score, see [the CI gate](harden.md#ci-gate-on-the-score).

## Tiers

The tier is the attacker's budget: tool calls and wall-clock time.

| Tier | Calls | Time |
|---|---|---|
| T1 | 150 | 15 min |
| T2 | 1,500 | 2 h |
| T3 | 6,000 | 8 h |

## Objectives

The attacker tries five Objectives on the web bundle. Verifiers decide whether each one was reached, from facts the attacker never sees; they never trust the attacker's own claims.

| Objective | Weight | Reached when |
|---|---|---|
| W1 Map | 15 % | The submitted endpoints cover at least 60 % of your `--routes` inventory, with at least half of the submitted endpoints correct. Without an inventory, Map is not attempted. |
| W2 Secrets | 20 % | A submitted value equals a planted Canary or a value the leak scan flagged. |
| W3 Logic | 25 % | A re-implementation of a protected function from `--logic` passes every one of its hidden test vectors. Without `--logic`, Logic is not attempted. |
| W4 Tamper | 20 % | A modified file runs with the attacker's marker in it and still behaves like the original. Without `--integrity`, there is no tamper check, so a small edit reaches it. |
| W5 Replay | 20 % | A submitted request gets a 2xx from a replica of your server that requires signed requests. |

Each Objective shows one of:

- **Achieved at T1/T2/T3:** the attacker reached it within that tier's limits.
- **Not achieved:** the attacker did not reach it within the run's budget.
- **Not attempted:** with the reason. Not attempted is left out of the score; it is not resistance.

## What the score means

For each Objective, resistance is 0 when it was reached within T1, 0.4 within T2, 0.7 within T3. When it was not reached, resistance is what the run's tier can show: 0.4 for a T1 run, 0.7 for T2, 1 for T3. A T1 run can therefore never score above 40: a small budget cannot show resistance beyond itself.

The RRS is the weighted sum of the resistances, times 100. When Objectives were not attempted, the other weights are scaled to sum to 1 and the Console says **Renormalised**. When more than 20 % of the weight was not attempted, the Assessment is **Inconclusive**, with no number and a reason.

Every score is shown with its scope: the agent, its version, the model, the toolbelt and the tier. Scores are comparable only within one scope.

## Honest limits

- **The agent is a scripted stand-in** until a real model is configured. Results measure the pipeline, not real resistance. The Console says so on every score.
- Untrusted code runs in a child process under Node's permission model, not a separate hosted account. A further adversarial review is pending before a real model agent is enabled.
- Harden's integrity check is a tamper signal, not tamper-proofing.
- The score covers what the Objectives test, on the bundle you uploaded. It says nothing about your server or other attacks.

See also: [Harden](harden.md), [Getting started](getting-started.md).
