# S0-a spend controls: design and what has been verified (2026-10-30)

Approved maximum for S0-a: **$50**. Four layers, from the inside out.

| Layer         | Control                                                                                                                                                                                                     | Status                                                             |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| 1. Per task   | `spend/task-guard.mjs` kills the run's process group when its running cost passes the cap minus a margin. Cap **$6**; margin **$2** until the dry run measures its accuracy, so it trips at **$4** computed | Accounting checked offline against 8 recorded runs (below)         |
| 2. Scheduling | The driver starts no new run once the sum of completed runs' reported totals (Claude Code's `total_cost_usd`), plus the cost of the run in flight, reaches **$42**                                          | Design; it uses the totals checked below                           |
| 3. Provider   | The pilot's Anthropic workspace has a monthly spend limit of **$45**                                                                                                                                        | Must be verified by the $1 test first (`spend/spend-stop-test.sh`) |
| 4. GitHub     | Standard runners are free on public repositories. Without a payment method, usage beyond the included amount is blocked                                                                                     | From GitHub's billing documentation                                |

## What the offline check showed

Run with `node spend/task-guard.mjs --replay <recording> --cap 0.01` against eight recorded Claude Code streams kept privately by the owner (Haiku 4.5 and Sonnet 5).

- **The price table is right.** Pricing each run's final usage reproduces Claude Code's own `total_cost_usd` exactly in 6 of 8 recordings. Of the other two:
  - one has no final usage;
  - one used a second model (the guard prices only the run's first model from the final usage; the running count covers every message).
- **Two causes of under-counting, both fixed:**
  1. Claude Code writes its prompt cache with a **1-hour lifetime**, billed at **2x input**. The first version priced it at the 5-minute rate (1.25x), and under-counted by 35–50%.
  2. The plain `assistant` events **omit thinking tokens**: 7 output tokens shown, 56 billed. The guard now also reads the raw `message_delta` usage that `--include-partial-messages` emits.
- **The remaining gap** on recordings made without partial messages: the running estimate is **1–9% below** the true total on most runs, **15% and 37%** on two. Hence the $2 margin, until the dry run measures the gap with partial messages on.

## Ways spend can still overshoot (residual risks)

- **The message in flight.** The guard can only stop a run between events. The message being generated when the cap trips still completes and is billed. Its size is bounded by the run's `max_tokens`; the margin absorbs typical messages.
- **Provider accounting delay.** Anthropic's documentation does not say how quickly a workspace spend limit takes effect, or how it rejects requests. The $1 test measures both:
  - the status and error type at rejection;
  - how far past $1 it lets spending go.
    If it has not stopped by $1.20, the provider limit is treated as **unproven**, and layers 1–2 carry the guarantee.
- **The key itself.** The agent can read its own pilot key. Used elsewhere, it can spend only up to the workspace limit. The key is revoked after the pilot.
- **Claude Code's own estimate** is labelled `costBasis: list`. The Console's figures are authoritative, so the driver reconciles with them after every task and stops on a difference over 10%.

## The $1 test (run by the owner, before any pilot run)

1. In the Console, create a test workspace with a monthly spend limit of **$1**, and one key in it. Save the key to a file with mode 600.
2. Run `! bash spend/spend-stop-test.sh <key-file>` in this session. The key never passes through Claude.
3. Read the result line. Compare the computed total with the Console's usage for that workspace.
4. Archive the test workspace and revoke its key.

Cost: at most $1.20, counted inside the $50.
