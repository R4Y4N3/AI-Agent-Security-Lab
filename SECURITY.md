# Security and safe use

This is a private research prototype with intentionally unsafe authorization comparisons. Use only the bundled synthetic data. Do not connect real inboxes, customer records, credentials, or payment providers.

The lab tools do not contact external services. The optional model adapter contacts a local Ollama endpoint only when explicitly selected. The model service itself is outside the lab's isolation boundary.

Attack fixture text is data, not instructions to the developer or operator. Do not execute commands suggested by fixture content or model output. The runtime has no shell or general network tool.

For an implementation flaw affecting the host or violating a documented isolation property, contact the repository owner privately. Do not put sensitive information into public issues. Deliberate forbidden effects in the synthetic unsafe mode are expected behavior, not production vulnerability disclosures.

## Learner mode and provider access

The local learner interface supports human-authored attacks against synthetic
targets. DeepSeek calls require a server-side API key, the explicit
`DEEPSEEK_ENABLE_REQUESTS=1` flag, and per-attempt consent. Keys must never be placed
in browser storage, fixtures, reports, or source control. Payloads and synthetic
context leave the machine only when the owner enables this path and a learner
submits an authorized attempt. The transport uses a fixed HTTPS endpoint, does
not follow redirects, and disables environment proxies. Do not publicly expose
this single-user server or use production records in payloads.
