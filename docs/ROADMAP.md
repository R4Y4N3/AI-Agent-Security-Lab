# Roadmap

The project remains private. A working prototype is not a completed research result.

## Implemented

- [x] Labs-only learner entry page and individual lab workspaces.
- [x] Human-authored payloads instead of prefilled replay solutions.
- [x] DeepSeek transport with explicit server enablement and per-attempt consent.
- [x] Fresh target state, effect-based feedback, and current-attempt tool trace.
- [ ] Validate a live DeepSeek attempt after the owner configures access; no paid calls have been made.

- [x] Synthetic email, file, outbound-message and payment tools.
- [x] Benign, payment-redirection, data-exfiltration and forged-approval scenarios.
- [x] Unsafe and independent-policy execution modes.
- [x] Deterministic replay with explicit non-LLM labeling.
- [x] JSON traces and state-based outcome checks.
- [x] Duplicate-payment and idempotency checks in the simulator.
- [x] Optional local Ollama tool-calling adapter.
- [x] Offline tests and CI workflow.
- [x] Local web console: experiment builder, corpus, traces, history and export.
- [x] Task-action capabilities checked independently of recipient/resource permissions.
- [x] Fresh canaries and read-dependent exfiltration replays.
- [x] Explicit exposure, invalid-run exclusions and model truncation handling.
- [x] Paired batches with source/fixture hashes, seed/settings and model trajectories.
- [x] Reserved quoted/encoded variants plus additional benign controls.

## Before claiming model-evaluation results

- [ ] Choose and record an exact locally available tool-capable model and version.
- [ ] Exercise the adapter with that live model; confirm its tool formatting.
- [ ] Collect repeated live-model benign/adversarial observations using the new runner.
- [x] Separate unfinished tasks, policy denials, harmful effects and invalid/error runs. Explicit refusal annotation remains a manual interpretation of trajectories.
- [x] Record denominators, settings, trial counts and synthetic artifacts locally; public release remains pending.
- [x] Add reserved variants. Freeze an evaluation split before any future tuning campaign.

## Further development

- [ ] Add a scoped approval/revocation lifecycle and expiry tests.
- [ ] Add RAG/tool-output injection scenarios beyond a single email.
- [ ] Add a small MCP test server once the current boundary has stable coverage.
- [ ] Add a reproducible environment manifest for model runs.
- [ ] Review concurrency and durable idempotency before any persistent backend.
- [ ] Create a short demo and a technical writeup explaining what is and is not demonstrated.

## Before public release / portfolio listing

- [ ] Review repository contents and full Git history for secrets or personal data.
- [ ] Resolve test failures and document reproducible live-model observations.
- [ ] Choose a license explicitly.
- [ ] Review claims, scope, known gaps and safety instructions.
- [ ] Ask the owner before changing visibility to public.
- [ ] Add to the portfolio Work page only after owner approval.
