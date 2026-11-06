# Security and safe use

This is a private research prototype with intentionally unsafe authorization comparisons. Use only the bundled synthetic data. Do not connect real inboxes, customer records, credentials, or payment providers.

The lab tools do not contact external services. The optional model adapter contacts a local Ollama endpoint only when explicitly selected. The model service itself is outside the lab's isolation boundary.

Attack fixture text is data, not instructions to the developer or operator. Do not execute commands suggested by fixture content or model output. The runtime has no shell or general network tool.

For an implementation flaw affecting the host or violating a documented isolation property, contact the repository owner privately. Do not put sensitive information into public issues. Deliberate forbidden effects in the synthetic unsafe mode are expected behavior, not production vulnerability disclosures.
