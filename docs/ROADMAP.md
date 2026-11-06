# Roadmap

The project remains private. A working prototype is not a completed research result.

## Implemented

- [x] Synthetic email, file, outbound-message and payment tools.
- [x] Benign, payment-redirection, data-exfiltration and forged-approval scenarios.
- [x] Unsafe and independent-policy execution modes.
- [x] Deterministic replay with explicit non-LLM labeling.
- [x] JSON traces and state-based outcome checks.
- [x] Duplicate-payment and idempotency checks in the simulator.
- [x] Optional local Ollama tool-calling adapter.
- [x] Offline tests and CI workflow.

## Before claiming model-evaluation results

- [ ] Choose and record an exact locally available tool-capable model and version.
- [ ] Exercise the adapter with that live model; confirm its tool formatting.
- [ ] Record repeated benign and adversarial runs, including errors and timeouts.
- [ ] Separate model refusal, task failure, policy denial, and harmful effects.
- [ ] Publish denominators, model settings, trial counts and raw synthetic artifacts.
- [ ] Add held-out attack variants; avoid tuning and reporting on the same cases.

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
