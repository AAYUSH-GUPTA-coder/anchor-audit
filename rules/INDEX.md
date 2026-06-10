# Rule index

50 rules across 8 categories. Severity reflects typical impact when the pattern is present and exploitable; always judge in context.

| ID | Rule | Severity | Category |
|----|------|----------|----------|
| 001 | [Missing signer check](./001-missing-signer-check.md) | Critical | Account validation |
| 002 | [Missing owner check](./002-missing-owner-check.md) | Critical | Account validation |
| 003 | [Missing discriminator check (type cosplay)](./003-missing-discriminator-check.md) | High | Account validation |
| 004 | [Account substitution](./004-account-substitution.md) | High | Account validation |
| 005 | [Sysvar spoofing](./005-sysvar-spoofing.md) | High | Account validation |
| 006 | [Missing rent-exemption check](./006-missing-rent-exemption-check.md) | Low | Account validation |
| 007 | [Account aliasing (duplicate mutable accounts)](./007-account-aliasing.md) | High | Account validation |
| 008 | [Uninitialized account use](./008-uninitialized-account-use.md) | High | Account validation |
| 009 | [Missing `mut` constraint](./009-missing-mut-constraint.md) | Medium | Account validation |
| 010 | [Missing or improper close constraint](./010-missing-close-constraint.md) | Medium | Account validation |
| 011 | [PDA seed collision](./011-pda-seed-collision.md) | High | PDA |
| 012 | [Missing bump validation](./012-missing-bump-validation.md) | Medium | PDA |
| 013 | [Non-canonical bump accepted](./013-non-canonical-bump-accepted.md) | High | PDA |
| 014 | [Predictable / attacker-controlled PDA seeds](./014-predictable-pda.md) | High | PDA |
| 015 | [Insecure PDA layout across upgrades](./015-insecure-pda-across-upgrades.md) | Medium | PDA |
| 016 | [Stored bump mismatch](./016-bump-mismatch.md) | Medium | PDA |
| 017 | [Arbitrary CPI (unvalidated target)](./017-arbitrary-cpi.md) | Critical | CPI |
| 018 | [CPI confused deputy](./018-cpi-confused-deputy.md) | High | CPI |
| 019 | [Missing program ID check on SPL CPIs](./019-missing-program-id-check-spl.md) | High | CPI |
| 020 | [Reentrancy via CPI](./020-reentrancy-via-cpi.md) | High | CPI |
| 021 | [Untrusted callback execution](./021-untrusted-callback.md) | High | CPI |
| 022 | [CPI invoked with attacker-controlled accounts](./022-cpi-with-attacker-accounts.md) | High | CPI |
| 023 | [Lamport arithmetic overflow / underflow](./023-lamport-overflow.md) | High | Math |
| 024 | [Token amount arithmetic overflow](./024-token-amount-overflow.md) | High | Math |
| 025 | [Precision loss (division before multiplication)](./025-precision-loss.md) | Medium | Math |
| 026 | [Incorrect rounding direction](./026-rounding-direction.md) | Medium | Math |
| 027 | [Token decimal mismatch](./027-token-decimal-mismatch.md) | Medium | Math |
| 028 | [Integer cast truncation](./028-integer-cast-truncation.md) | Medium | Math |
| 029 | [Off-by-one errors](./029-off-by-one.md) | Low | Math |
| 030 | [Missing authorization on privileged instruction](./030-missing-authorization.md) | Critical | Auth |
| 031 | [Reinitialization attack](./031-reinitialization-attack.md) | High | Auth |
| 032 | [Closed account revival](./032-closed-account-revival.md) | High | Auth |
| 033 | [`init_if_needed` misuse](./033-init-if-needed-misuse.md) | High | Auth |
| 034 | [Missing `has_one` relationship enforcement](./034-missing-has-one.md) | High | Auth |
| 035 | [Insecure admin transfer (no acceptance handshake)](./035-insecure-admin-transfer.md) | Medium | Auth |
| 036 | [Missing pause / freeze guards](./036-missing-pause-guards.md) | Low | Auth |
| 037 | [Clock / time-based logic without bounds](./037-clock-manipulation.md) | Medium | Auth |
| 038 | [Missing `address` validation on fixed-identity accounts](./038-missing-address-validation.md) | Medium | Constraints |
| 039 | [Constraint evaluation stage (pre- vs post-state)](./039-constraint-evaluation-stage.md) | Medium | Constraints |
| 040 | [`realloc` without zero-init](./040-realloc-zero-init.md) | Medium | Constraints |
| 041 | [`init` without `payer` (or wrong payer)](./041-missing-payer-on-init.md) | Low | Constraints |
| 042 | [Incorrect `space` allocation](./042-incorrect-space-allocation.md) | Medium | Constraints |
| 043 | [`Account` vs `AccountInfo` misuse](./043-account-vs-account-info.md) | High | Constraints |
| 044 | [Token account owner unverified](./044-token-account-owner-unverified.md) | High | SPL Token |
| 045 | [Token mint unverified](./045-token-mint-unverified.md) | High | SPL Token |
| 046 | [Associated token account assumption errors](./046-ata-assumption-errors.md) | Medium | SPL Token |
| 047 | [Token program ID hardcoded vs. validated](./047-token-program-id-hardcoded.md) | Medium | SPL Token |
| 048 | [Compute budget abuse (unbounded work)](./048-compute-budget-abuse.md) | Medium | Runtime |
| 049 | [Log spam / excessive logging DoS](./049-log-spam-dos.md) | Low | Runtime |
| 050 | [Stack / CPI depth exhaustion](./050-stack-overflow-deep-cpi.md) | Low | Runtime |

## Severity counts

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High | 21 |
| Medium | 17 |
| Low | 8 |
