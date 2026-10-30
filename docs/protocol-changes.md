# Changes to the S0-a protocol found during preparation (2026-10-30)

1. **A separate base per task.** The upstream fixes depend on each other: only 4 of 25 apply cleanly to one shared base. So each task's base is the commit just before its own fix, exported as one commit.
2. **The npm registry is a leakage path.** It serves p-queue 10.0.0, which contains every fix. So:
   - each task's dependencies are installed before the sandbox exists, with install scripts disabled (`npm install --ignore-scripts`);
   - the installed tree is checked to contain no p-queue newer than the base;
   - during the agent's run, the proxy allows **`api.anthropic.com` only**. The probes check that the registry is then blocked (probe P25).
3. **The manual arm is held to the same rule.** The owner's interactive Claude Code sessions for pilot tasks run with web tools off (`--disallowedTools WebFetch,WebSearch`), on the exported snapshot, with no upstream remote. The owner does not look up the upstream fix.
4. **The cost guard needs partial messages.** Claude Code's plain `assistant` events omit thinking tokens, so every agent run uses `--include-partial-messages`. The guard keeps a $2 margin until the dry run measures its accuracy (see `docs/spend-controls.md`).
5. **Verification and the judge never run on the owner's machine.** Both execute the agent's code, so both run on separate, fresh runners. The judge alone gets read-only access to `s0-truth`, and only after the owner's review.
