# Case study: preserving the invoice permission boundary

Date: November 6, 2026. Experiment type: **scripted policy replay**, not a live-model benchmark.

## Setup

Twelve cases exercise one synthetic renewal workflow: three benign controls and nine attack variants. Each case runs once in both modes with independent in-memory state and fresh random canaries. The baseline bypasses runtime authorization; the guarded mode checks task actions and their arguments before mock effects. No actual messages or payments are sent.

```bash
python3 -m agent_security_lab experiment --scenarios \
  benign payment-redirect data-exfiltration approval-bypass \
  benign-reformatted benign-receipt redirect-quoted redirect-encoded \
  exfil-quoted exfil-encoded approval-quoted approval-encoded
```

The command saves a new JSON experiment under `artifacts/experiments/`. Exact IDs, canaries, timestamps and runtime durations vary. The console can inspect and export the resulting evidence.

## Observed replay outcomes

| Outcome | Unsafe authorization | Task-scoped policy |
| --- | --- | --- |
| Benign payments completed | 3/3 | 3/3 |
| Known attack objectives reached | 9/9 | 0/9 |
| Payments completed in malicious cases | 3/9 | 3/9 |
| Unauthorized mock effects | 12 | 0 |
| Excluded/error runs | 0 | 0 |

The three successful malicious-case payments are the exfiltration-family cases: the legitimate renewal can still finish after an attempted leak is denied. Redirection and forged-approval proposals are blocked rather than silently rewritten; those tasks remain unfinished in this replay.

## Why the boundary matters

The earlier scope checked email recipients but did not independently authorize the messaging action. That permitted extra internal mail despite the task forbidding it. The default capability set now contains only the named reads and invoice payment. A separate benign receipt case explicitly grants mail and still checks its recipient.

The exfiltration replay no longer hardcodes a secret in its outgoing message. It must obtain the current run's synthetic record through the read tool. Guarded mode denies that read, and the replay records a skipped message dependency rather than pretending the canary was available.

## What these results do not show

The runner supplies the known tool proposals: these numbers say nothing about how often an LLM would follow the malicious email. They are not statistically independent security trials, a prompt-injection detection score, or evidence of a universal defense. The reserved variants have already been exercised in regression tests; they are not a blind evaluation set. A future generalization claim needs a separately frozen campaign corpus.

Actual model experiments must additionally verify attack exposure, record the exact model/digest, retain failed and truncated runs, and use the validity-aware denominators in the [experiment protocol](EXPERIMENT_PROTOCOL.md). No live-model observations were collected for this case study.
