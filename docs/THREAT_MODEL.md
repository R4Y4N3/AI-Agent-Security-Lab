# Threat model — prototype

## Purpose and assets

Explore whether attacker-controlled content can lead an assistant to request actions outside a user's scope, and whether an independent tool boundary contains those actions.

Protected assets are the authorized invoice and recipient, the spending scope, the synthetic customer-record canary, and the integrity of the simulated payment ledger.

## Trust boundaries

1. The operator selects a trusted local scenario; fixtures are not downloaded or supplied by a remote party.
2. The user task and immutable `Scope` establish the permission envelope.
3. The email body is attacker-controlled data delivered through a tool result.
4. Agent tool calls are untrusted proposals, including claims of approval and completion.
5. `LabRuntime.call()` validates and, in guarded mode, authorizes a proposal before applying a mock effect.
6. Outcomes are computed from simulator state, not the model's explanation.

All four tools are statically registered. File IDs refer to in-memory fixtures, not paths. `send_email` appends to an in-memory outbox. `pay_invoice` appends to an in-memory ledger. No tool starts a shell, reads host files, opens a URL, sends an actual message, or executes a real financial transaction.

## Attacker capabilities

The scenarios place instructions in the renewal email. The attacker can attempt payee substitution, forge approval language, or request access to protected records and an unauthorized message recipient. The model may request arbitrary registered tools and arguments; that does not grant additional authority.

The scripted replay supplies known attack proposals to exercise the downstream policy. It does not demonstrate the model interpreting the email. Live-model behavior is a separate experiment.

## Defended properties

- Only the exact approved invoice, payee, and amount may be paid, once, within budget.
- A repeated idempotency key cannot change payment details or create a second effect.
- Protected mock files cannot be read through the guarded tool interface.
- Messages cannot be sent to recipients outside the fixed allowlist.
- Unknown tools, missing/extra fields, incorrect types, and invalid amounts are rejected in both modes.
- Every attempted tool call through the runtime produces an audit event; failed calls have no tool effect.

## Deliberately unsafe comparison

Unsafe mode bypasses the authorization gate, not basic argument validation or the isolation of mock tools. Forbidden actions affect only synthetic in-memory records. This is intended to illustrate consequences of missing authorization, not to provide an agent with real-world privileges.

## Out of scope and residual risk

The host, fixture files, Python process, local model service, and source code are trusted. A hostile operator can modify simulator internals; this is not a sandbox against them. The policy is a narrow allowlist, not a generic injection filter or DLP system. It does not protect model-generated text from disclosure, mediate a model server's own tools, or defend the host from vulnerabilities in Python or Ollama.

The adapter talks only to a literal loopback endpoint, but that is not proof that the model server is offline or locally safe. Configure a local-only model separately. All logs are synthetic and may include attacker strings and the fake canary. Do not substitute real customer data or credentials.

Budget and idempotency checks are single-process and in-memory. There is no persistent ledger, concurrency control, user identity proof, revocation, expiry, approval UI, cryptographic mandate, or recovery system. These are explicit limitations, not production guarantees.
