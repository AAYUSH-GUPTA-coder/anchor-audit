---
name: anchor-audit
description: Audits Anchor programs on Solana for security vulnerabilities. Use this skill when reviewing, auditing, or checking Solana smart contract code written with the Anchor framework. Covers signer checks, account validation, CPI safety, PDA seeds, lamport arithmetic, SPL token handling, and Anchor-specific constraint vulnerabilities.
---

# anchor-audit

A security checklist for Anchor programs on Solana, backed by a 50-rule catalog in [`rules/`](rules/). Each rule names a concrete vulnerable pattern, the fix, and what to grep for.

## When to invoke

Use this skill whenever the user asks to audit, review, security-check, or "look for bugs in" Solana program code written with the Anchor framework (Rust files under a `programs/` directory, `#[program]` modules, `#[derive(Accounts)]` structs, `Account<'info, T>` types). It applies to full-program audits, single-instruction reviews, and pre-deployment checks. It does not apply to non-Anchor native programs (Pinocchio, raw `solana-program`) beyond the subset of rules that are framework-agnostic, nor to client/TypeScript code.

## Audit workflow

Work through these steps in order. Pull in the relevant `rules/NNN-*.md` file for any pattern you suspect — each contains a detection heuristic and a fix.

1. **Discover entry points.** Find every `#[program]` module and list its instruction handlers. Each public handler is an attack surface.
2. **Enumerate accounts and constraints.** For each handler, open its `#[derive(Accounts)]` struct. Note every account's type (`Signer`, `Account<T>`, `AccountInfo`/`UncheckedAccount`, `Program`, `Sysvar`, `InterfaceAccount`) and its constraints (`mut`, `has_one`, `seeds`/`bump`, `address`, `constraint`, `token::*`, `init`, `close`, `realloc`).
3. **Run the rule catalog.** For each handler/account pair, walk the rule catalog below. Prioritize Critical and High rules. For each candidate, apply the rule file's *detection heuristic* against the actual code before concluding.
4. **Trace value and authority flow.** Follow lamports, token amounts, and authority/PDA signing through each handler. Confirm checked arithmetic (Rules 023–028), correct authorization (Rules 001, 030, 034), and validated CPIs (Rules 017–022).
5. **Produce findings.** Report each confirmed issue using the finding template below. Only report patterns you can point to in the source; note uncertain ones separately as "needs manual review."

## Rule catalog

Full table with severities in [rules/INDEX.md](rules/INDEX.md).

**Account validation**
- [001 Missing signer check](rules/001-missing-signer-check.md) · [002 Missing owner check](rules/002-missing-owner-check.md) · [003 Missing discriminator check](rules/003-missing-discriminator-check.md) · [004 Account substitution](rules/004-account-substitution.md) · [005 Sysvar spoofing](rules/005-sysvar-spoofing.md) · [006 Missing rent-exemption check](rules/006-missing-rent-exemption-check.md) · [007 Account aliasing](rules/007-account-aliasing.md) · [008 Uninitialized account use](rules/008-uninitialized-account-use.md) · [009 Missing mut constraint](rules/009-missing-mut-constraint.md) · [010 Missing close constraint](rules/010-missing-close-constraint.md)

**PDA safety**
- [011 PDA seed collision](rules/011-pda-seed-collision.md) · [012 Missing bump validation](rules/012-missing-bump-validation.md) · [013 Non-canonical bump accepted](rules/013-non-canonical-bump-accepted.md) · [014 Predictable PDA](rules/014-predictable-pda.md) · [015 Insecure PDA across upgrades](rules/015-insecure-pda-across-upgrades.md) · [016 Bump mismatch](rules/016-bump-mismatch.md)

**CPI safety**
- [017 Arbitrary CPI](rules/017-arbitrary-cpi.md) · [018 CPI confused deputy](rules/018-cpi-confused-deputy.md) · [019 Missing program ID check (SPL)](rules/019-missing-program-id-check-spl.md) · [020 Reentrancy via CPI](rules/020-reentrancy-via-cpi.md) · [021 Untrusted callback](rules/021-untrusted-callback.md) · [022 CPI with attacker accounts](rules/022-cpi-with-attacker-accounts.md)

**Math and value handling**
- [023 Lamport overflow](rules/023-lamport-overflow.md) · [024 Token amount overflow](rules/024-token-amount-overflow.md) · [025 Precision loss](rules/025-precision-loss.md) · [026 Rounding direction](rules/026-rounding-direction.md) · [027 Token decimal mismatch](rules/027-token-decimal-mismatch.md) · [028 Integer cast truncation](rules/028-integer-cast-truncation.md) · [029 Off-by-one](rules/029-off-by-one.md)

**Authorization and lifecycle**
- [030 Missing authorization](rules/030-missing-authorization.md) · [031 Reinitialization attack](rules/031-reinitialization-attack.md) · [032 Closed account revival](rules/032-closed-account-revival.md) · [033 init_if_needed misuse](rules/033-init-if-needed-misuse.md) · [034 Missing has_one](rules/034-missing-has-one.md) · [035 Insecure admin transfer](rules/035-insecure-admin-transfer.md) · [036 Missing pause guards](rules/036-missing-pause-guards.md) · [037 Clock manipulation](rules/037-clock-manipulation.md)

**Anchor constraint hygiene**
- [038 Missing address validation](rules/038-missing-address-validation.md) · [039 Constraint evaluation stage](rules/039-constraint-evaluation-stage.md) · [040 realloc zero-init](rules/040-realloc-zero-init.md) · [041 Missing payer on init](rules/041-missing-payer-on-init.md) · [042 Incorrect space allocation](rules/042-incorrect-space-allocation.md) · [043 Account vs AccountInfo](rules/043-account-vs-account-info.md)

**SPL token specifics**
- [044 Token account owner unverified](rules/044-token-account-owner-unverified.md) · [045 Token mint unverified](rules/045-token-mint-unverified.md) · [046 ATA assumption errors](rules/046-ata-assumption-errors.md) · [047 Token program ID hardcoded](rules/047-token-program-id-hardcoded.md)

**SVM / runtime**
- [048 Compute budget abuse](rules/048-compute-budget-abuse.md) · [049 Log spam DoS](rules/049-log-spam-dos.md) · [050 Stack overflow / deep CPI](rules/050-stack-overflow-deep-cpi.md)

## Output format

Rate each finding by impact and exploitability:

- **Critical** — direct loss of funds or full privilege takeover, reachable by any user.
- **High** — fund loss or privilege escalation under realistic conditions, or a missing core check.
- **Medium** — exploitable with constraints, or correctness/accounting bugs that leak value.
- **Low** — hardening, robustness, and availability issues with limited direct impact.

Lead with a summary table, then one section per finding sorted Critical → Low:

```markdown
## Summary
| Severity | Count |
|----------|-------|
| Critical | N |
| High     | N |
| Medium   | N |
| Low      | N |

## Findings

### [CRITICAL] Rule 017: Arbitrary CPI in `transfer_tokens`
**File:** `programs/my-vault/src/lib.rs:142`

**Description:** The token program is passed as an unvalidated `AccountInfo`...
**Vulnerable code:**
```rust
// the offending snippet
```
**Recommendation:** Type it as `Program<'info, Token>` so Anchor pins the ID...
**Reference:** rules/017-arbitrary-cpi.md
```

For each finding include: severity + rule ID + short title, the file and line, a description tied to the rule, the vulnerable snippet, a concrete recommendation, and a reference to the rule file.

## Limitations

This skill performs **static, pattern-based review**. It is a first-pass triage aid, not a substitute for a professional human audit. It can miss vulnerabilities — especially business-logic flaws, economic/oracle attacks, and bugs that span multiple instructions or require protocol-specific context — and it can produce false positives that look like a pattern but are safe in context. Always confirm each finding against the actual code path, and never treat a clean result as authorization to deploy to mainnet. Recommend an independent professional audit and thorough testing before any production deployment.
