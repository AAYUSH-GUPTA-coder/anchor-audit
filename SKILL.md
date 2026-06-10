---
name: anchor-audit
description: Audits Anchor programs on Solana for security vulnerabilities. Use this skill when reviewing, auditing, or checking Solana smart contract code written with the Anchor framework. Covers signer checks, account validation, CPI safety, PDA seeds, lamport arithmetic, SPL token handling, and Anchor-specific constraint vulnerabilities.
---

# anchor-audit

<!-- SKELETON (Phase 1). Body sections are filled in during Phase 2 alongside
     the rule catalog. Keep this file under 600 lines; detailed rule content
     lives in /rules/ and is pulled in only when relevant. -->

## When to invoke

<!-- TODO(Phase 2): one paragraph telling Claude exactly when this skill
     applies — auditing, reviewing, or checking Anchor/Solana program code. -->

## Audit workflow

<!-- TODO(Phase 2): step-by-step instructions:
     1. Discover entry points (instruction handlers in #[program] modules)
     2. Enumerate accounts (#[derive(Accounts)] structs and constraints)
     3. Run the rule catalog against each handler/account pair
     4. Produce findings in the output format below -->

## Rule catalog

<!-- TODO(Phase 2): one bullet per rule linking to /rules/NNN-name.md,
     grouped by category (Account validation, PDA, CPI, Math, Auth,
     Constraints, SPL Token, Runtime). 50 rules total. -->

See [rules/INDEX.md](rules/INDEX.md) for the full catalog.

## Output format

<!-- TODO(Phase 2): severity levels (Critical/High/Medium/Low), the
     per-finding template, and the summary table format. -->

## Limitations

<!-- TODO(Phase 2): what the skill does and does not catch; static
     pattern-matching only, no dynamic analysis; recommend a professional
     manual audit before any mainnet deployment. -->
