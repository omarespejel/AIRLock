# Copilot Instructions

Read and follow `/AGENTS.md`, then `/.codex/START_HERE.md`. They are the
canonical repository instructions and review rules.

When reviewing or generating code, prioritize:

- lossless AuditIR and exporter behavior;
- fail-closed results and explicit coverage;
- adversarial regressions at untrusted boundaries;
- separation of AIR, statement, protocol/transcript, and evidence claims.

Do not duplicate or weaken the rules in `AGENTS.md`.
