#!/usr/bin/env node
// Per-task spend guard for the S0 pilot (no dependencies; Node 18+).
//
//   node task-guard.mjs --cap 6 --log run.jsonl -- <command> [args...]
//       Runs the command (Claude Code with --output-format stream-json) in its own process
//       group, passes its stdout through to the log, and adds up the cost of every
//       assistant message from its usage. At the cap it sends SIGTERM to the whole group,
//       then SIGKILL after 5 s, and exits with code 3.
//   node task-guard.mjs --replay recorded.jsonl [--cap N]
//       Computes the same figures for a recorded stream, to check the accounting.
//
// Cost is computed at list price per million tokens. Each message id is counted once,
// with the largest usage seen for it. Cache writes are priced by their lifetime (Claude
// Code writes 1-hour entries, at 2x input). A model missing from the table is charged at
// the highest price in the table, so an unknown model can only stop a run sooner.
//
// Accuracy: the plain stream-json `assistant` events leave out thinking tokens (measured
// on recorded runs: 7 output tokens shown, 56 billed). Run Claude Code with
// --include-partial-messages so that each message's `message_delta` usage, which includes
// them, reaches the guard. --margin stops the run that many dollars before the cap, to
// absorb the message still in flight.
import { spawn } from "node:child_process";
import { createReadStream, createWriteStream } from "node:fs";
import { createInterface } from "node:readline";

// USD per million tokens: input, output, cache read. Cache writes: 1.25x input for 5-minute
// entries, 2x input for 1-hour entries. Source: the claude-api reference (cached
// 2026-10-06); checked against Claude Code's own totals on recorded runs. Older models are
// here only for replays.
const PRICES = {
  "claude-opus-5-5": [4, 20, 0.2],
  "claude-sonnet-5-5": [2, 10, 0.2],
  "claude-haiku-5-5": [0.1, 0.5, 0.01],
  "claude-sonnet-5": [2, 10, 0.2],
  "claude-haiku-4-5": [1, 5, 0.1],
  "claude-fable-5-1": [10, 50, 0.25],
};
const MAX_PRICE = [10, 50, 1];

function priceFor(model) {
  const key = Object.keys(PRICES).find((k) => (model ?? "").startsWith(k));
  return key ? PRICES[key] : MAX_PRICE;
}

/** The dollar cost of one usage record at list price. */
export function usageCost(model, u) {
  const [inp, out, read] = priceFor(model);
  const created = u.cache_creation_input_tokens ?? 0;
  const fiveMin = u.cache_creation?.ephemeral_5m_input_tokens ?? 0;
  // Without a breakdown, price every cache write as a 1-hour write (the higher price).
  const oneHour = u.cache_creation ? (u.cache_creation.ephemeral_1h_input_tokens ?? 0) : created;
  return ((u.input_tokens ?? 0) * inp + (u.output_tokens ?? 0) * out +
    fiveMin * inp * 1.25 + oneHour * inp * 2 + (u.cache_read_input_tokens ?? 0) * read) / 1e6;
}

export class Ledger {
  #messages = new Map();
  #current = null; // the message a partial-message stream is in
  reported = null;
  finalUsageCost = null;
  #merge(id, model, usage) {
    const prev = this.#messages.get(id) ?? { model, usage: {}, cache_creation: undefined };
    for (const [k, v] of Object.entries(usage)) {
      if (typeof v === "number") prev.usage[k] = Math.max(prev.usage[k] ?? 0, v);
    }
    if (usage.cache_creation) prev.usage.cache_creation = usage.cache_creation;
    prev.model = prev.model ?? model;
    this.#messages.set(id, prev);
  }
  add(event) {
    if (event?.type === "result") {
      if (typeof event.total_cost_usd === "number") this.reported = event.total_cost_usd;
      const mu = event.modelUsage ?? {};
      const model = Object.keys(mu)[0];
      if (event.usage && model) this.finalUsageCost = usageCost(model, event.usage);
      return;
    }
    if (event?.type === "assistant" && event.message?.id && event.message.usage) {
      this.#merge(event.message.id, event.message.model, event.message.usage);
      return;
    }
    // --include-partial-messages: raw stream events carry the complete usage.
    const ev = event?.type === "stream_event" ? event.event : null;
    if (ev?.type === "message_start" && ev.message?.id) {
      this.#current = { id: ev.message.id, model: ev.message.model };
      if (ev.message.usage) this.#merge(ev.message.id, ev.message.model, ev.message.usage);
    } else if (ev?.type === "message_delta" && ev.usage && this.#current) {
      this.#merge(this.#current.id, this.#current.model, ev.usage);
    }
  }
  get cost() {
    let usd = 0;
    for (const { model, usage } of this.#messages.values()) usd += usageCost(model, usage);
    return usd;
  }
}

function args() {
  const a = process.argv.slice(2);
  const sep = a.indexOf("--");
  const opts = { cap: Number.POSITIVE_INFINITY, margin: 0, cmd: sep >= 0 ? a.slice(sep + 1) : [] };
  const head = sep >= 0 ? a.slice(0, sep) : a;
  for (let i = 0; i < head.length; i += 2) {
    if (head[i] === "--cap") opts.cap = Number(head[i + 1]);
    else if (head[i] === "--log") opts.log = head[i + 1];
    else if (head[i] === "--margin") opts.margin = Number(head[i + 1]);
    else if (head[i] === "--replay") opts.replay = head[i + 1];
  }
  return opts;
}

async function replay(file, cap) {
  const ledger = new Ledger();
  let tripped = null;
  for await (const line of createInterface({ input: createReadStream(file) })) {
    try { ledger.add(JSON.parse(line)); } catch { continue; }
    if (tripped === null && ledger.cost > cap) tripped = ledger.cost;
  }
  console.log(JSON.stringify({
    file: file.split("/").pop(),
    streamedUsd: +ledger.cost.toFixed(6),
    finalUsagePricedUsd: ledger.finalUsageCost === null ? null : +ledger.finalUsageCost.toFixed(7),
    claudeCodeReportedUsd: ledger.reported,
    wouldStopAt: tripped,
  }));
}

function run({ cap, margin, log, cmd }) {
  if (!Number.isFinite(cap) || cmd.length === 0) {
    console.error("usage: task-guard.mjs --cap <usd> [--log file] -- <command> [args...]");
    process.exit(2);
  }
  const out = log ? createWriteStream(log, { flags: "a" }) : process.stdout;
  const child = spawn(cmd[0], cmd.slice(1), { detached: true, stdio: ["ignore", "pipe", "inherit"] });
  const ledger = new Ledger();
  let stopped = false;
  const killGroup = (sig) => { try { process.kill(-child.pid, sig); } catch { /* already gone */ } };
  createInterface({ input: child.stdout }).on("line", (line) => {
    out.write(line + "\n");
    try { ledger.add(JSON.parse(line)); } catch { return; }
    if (!stopped && ledger.cost > cap - margin) {
      stopped = true;
      console.error(`task-guard: cap $${cap} reached at $${ledger.cost.toFixed(4)}: stopping the run`);
      killGroup("SIGTERM");
      setTimeout(() => killGroup("SIGKILL"), 5000).unref();
    }
  });
  child.on("close", (code, signal) => {
    const summary = { capUsd: cap, marginUsd: margin, computedUsd: +ledger.cost.toFixed(6), reportedUsd: ledger.reported, stoppedByGuard: stopped, exitCode: code, signal };
    console.error("task-guard: " + JSON.stringify(summary));
    process.exitCode = stopped ? 3 : (code ?? 1);
  });
}

const opts = args();
if (opts.replay) await replay(opts.replay, opts.cap);
else run(opts);
