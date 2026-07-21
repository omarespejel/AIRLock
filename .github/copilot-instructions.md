# Copilot / AI-agent instructions — AIRLock

This repository builds adversarial AIR assurance tooling for Stwo.

## Priorities

1. Soundness of AuditIR and static gates over style.
2. Fail closed: UNKNOWN / UNSUPPORTED / timeout are never green.
3. Keep AIR, statement-binding, protocol, and evidence lanes separate.
4. Seeded defects must be caught by generic rules.

## Do not

- Claim whole-system STARK security from an AIR lint.
- Hard-code named attacks instead of generic support/encoder/phase checks.
- Quietly omit executable surfaces from the coverage manifest.
