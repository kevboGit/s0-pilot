# Job A — development workflow design (preparation only; NOT runnable yet)

**Status: PREPARATION, 2026-11-09. UNAPPROVED; agent execution NO-GO.** This documents the
smallest GitHub-native "Job A" that could eventually let Claude Code solve ONE real S0-a
pilot task and emit the existing `submission.json` + `patch.diff` artifact the proven
two-runner verifier consumes. Nothing here runs an agent, a candidate, or a paid model
call, and no credential exists yet. The companion workflow skeleton is
`.github/workflows/dev-jobA-pqueue.yml`.

This is gated by `ticket-dispatcher/docs/plans/s0a-security-gates.md` **Gate A** (UNAPPROVED).

## 1. Selected first-pilot task (candidate)

- **Candidate: `C1`** — the p-queue "`isSaturated` is `false` when concurrency is lowered
  below the running tasks" task (source change **+2 / −2**, hidden test **+20**, the smallest,
  area **State**): a self-contained boolean getter — the least ambiguous first task.
  Alternative: `A2` (event-order, **+2 / −1**). The underlying upstream fix commit id is
  **deliberately not recorded in this public repo** (it would reveal the reference solution
  and the hidden tests); task identity lives only in the private `s0-truth/docs/tasks.md`.
- **Base = `fix~1`**: a public upstream p-queue commit (the pre-fix state the agent works on).
  The hidden tests are the test changes _added by the fix_, so they do **not** exist at base —
  a base checkout is inherently hidden-test-free. The exact base SHA is
  **orchestrator-supplied at dispatch** (same pattern the two-runner uses for `base`), never
  derived from the fix id in the agent context, and never the fix commit itself.
- **Matched-pair caveat (correction 2).** The authorized experiment is **ten tasks in five
  matched pairs** with a coin-flip lane assignment recorded before any work
  (`s0-truth/docs/tasks.md`). `C1` is only usable as the first autonomous pilot **if the
  recorded coin flip put `C1` in the autonomous lane**; otherwise use the autonomous-lane
  member of the simplest available pair. This selection is a _candidate for a separate,
  narrow pilot approval_ and does **not** reduce or replace the ten-task / five-pair plan.

## 2. Data flow

```
owner-authorized {task=C1, attempt=1, base=<orchestrator-supplied fix~1 sha>, ticket}
      │  (manual workflow_dispatch; inputs validated, env-passed, never inlined in shell)
      ▼
[Job A, s0-pilot runner]  checkout public upstream p-queue @ base (source + base's own
      │                    passing tests; NO hidden tests present) → hardened Claude Code
      │                    edits ONLY source/** → git diff source/ → submission.json+patch.diff
      ▼
upload-artifact "submission" (exactly submission.json + patch.diff, flat)   [NO push/PR/merge]
      ▼
(separately, later, under its own approval) the PROVEN two-runner verifier:
   fetch-artifact.py → handoff.py (safe-extract + authorize + SHA-256 bind) → unprivileged,
   net-isolated, source-only apply.  ← unchanged; this design must not weaken it.
```

## 3. Artifact contract (identical to the proven path — reused, not changed)

- `submission.json` — exactly `{schema:"s0.submission/v1", task, attempt, base, patch:"patch.diff"}`.
- `patch.diff` — a `git diff` touching **only `source/**`** (100644 text; no renames outside
source; the validator's full policy in `s0-truth/validation/submission-validator.md`).
- Two flat entries at the zip root — the exact shape `fixture-artifact.yml` already emits and
  the live two-runner run `42684506664` consumed. Job A changes **what** produces the patch
  (Claude Code vs. a synthetic generator), never the **format**. Compatibility is verified
  locally against the real `validate-submission.py` with synthetic fixtures only (§7).

## 4. Agent invocation (explicit controls)

- **Trigger:** `workflow_dispatch` only (manual). Inputs `task`, `attempt`, `base`,
  `ticket_ref`, strictly validated, passed via env, never interpolated into shell text.
- **Claude Code:** a pinned version (exact `@x.y.z`, installed from the signed channel);
  `--setting-sources user` only; `disableAllHooks`; no MCP servers; no plugins/skills/memory;
  a restricted allowed-tool set (edit/read/write within the work tree + a minimal shell);
  a fresh `CLAUDE_CONFIG_DIR`/`HOME` per run.
- **Timeout:** job `timeout-minutes: 30` **and** an agent-level wall-clock/turn cap.
- **Scope:** the agent may modify only `source/**`; the packaging step rejects any out-of-
  `source/` change before upload (defense in depth; the verifier re-checks independently).
- **No repo writes:** `permissions: contents: read` only; no `GITHUB_TOKEN` write scope; the
  agent has no git push, no PR, no merge, no deploy.

## 5. Credential, network, and spend isolation (the core NO-GO item)

- **Model credential (R-cred, correction 4 & 7 — NO-GO until resolved).** A reusable model
  credential must **never** be reachable by agent-controlled shell commands or candidate code.
  The intended boundary is a **credential-injecting egress proxy**: the API key lives only in
  the proxy; Claude Code is pointed at it (`ANTHROPIC_BASE_URL=http://127.0.0.1:<proxy>`), and
  the agent step's environment contains **no** key. **Critically, the proxy must run in a
  SEPARATE namespace/container (or a separate runner) — not a same-uid sidecar on the agent's
  runner**: a same-uid agent (and the untrusted `npm test` upstream scripts it may run) could
  otherwise read the key via `/proc/<pid>/environ` or shared fds. The "unreachable" guarantee
  rests on OS/namespace isolation, **not** Claude Code's tool allowlist. **This proxy is not
  implemented or verified yet** → the first real Claude Code run is **NO-GO** until it exists
  and an adversarial check confirms the agent cannot read the key (env/fd/`/proc`/filesystem
  scan from a same-uid process).
- **Network egress.** Default-deny; allow only the proxy endpoint and the public npm/p-queue
  fetch needed to prepare the base. No access to s0-truth, hidden tests, or private creds.
- **Spend.** The **$50 is a maximum experimental budget, not an authorization**
  (`s0-pilot/docs/spend-controls.md`). A credits-only / per-run-capped key, a provider spend
  cap, and a per-run turn/token ceiling; every spend and every run approved separately.
- **Repository secrets.** None added by this preparation. If a key is ever provisioned it
  goes behind the proxy, scoped and capped — a separate, approved step.

## 6. What is kept entirely OUT of Job A (correction: isolation)

- The private **hidden tests**, the **reference solutions**, and the **verifier code** live
  in `s0-truth` and are never checked out, mounted, or referenced by Job A.
- No **private repository credentials**; no write token to s0-pilot or s0-truth.
- Job A and the private verification jobs stay on **separate runners** (the proven pattern).

## 7. Output-format compatibility test (synthetic only)

`scripts/jobA-format-check.sh` (preparation helper) builds a **synthetic** C1-shaped
submission (`submission.json` + a tiny `source/**`-only `patch.diff`) and runs the **real,
unmodified** `s0-truth/validation/validate-submission.py` against it, asserting `ok:true`.
This proves Job A's artifact format is consumable by the existing verifier **without changing
any verification component** and **without executing Claude Code or any candidate**.

## 8. Compatibility with the proven two-runner verifier

Job A emits the exact `s0.submission/v1` two-file artifact the verifier already accepts
(demonstrated live by run `42684506664`). The verifier's authority anchoring, safe-extract,
SHA-256 bind, root-owned staging, network isolation, and unprivileged source-only apply are
**unchanged**. Job A adds no new trust into that path; it only produces an input the path
already validates independently.

## 9. GO/NO-GO blockers before the first actual Claude Code run

1. **Credential-isolation proxy** implemented + adversarially verified (R-cred). **NO-GO** until done.
2. **Gate A** written owner GO/NO-GO (UNAPPROVED) + a separate **spend** authorization.
3. **Recorded coin-flip** lane assignment confirming the pilot task is autonomous-lane.
4. **Evaluation residuals R1/R2** acknowledged as accepted for this non-adversarial pilot
   (they are NOT solved; production needs **Gate B**).
5. A hardened Claude Code image/version pinned with conformance (no hook/skill/MCP loads;
   `apiKeySource` none with the key only at the proxy).

Until all hold, Job A stays a prepared, non-executed skeleton.
