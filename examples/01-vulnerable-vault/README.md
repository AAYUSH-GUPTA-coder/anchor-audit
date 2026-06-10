# 01-vulnerable-vault

> **WARNING: This program is intentionally insecure. Never deploy it to devnet or mainnet.**

An Anchor vault program written with 18 known security vulnerabilities across 7 rule categories. It is used as the primary regression target for `anchor-audit`: the CLI is expected to identify all findings documented in [EXPECTED_FINDINGS.md](./EXPECTED_FINDINGS.md).

## Program overview

A simple token vault that lets users deposit, withdraw, and close positions. The protocol admin can collect fees. The program is structurally plausible but deliberately omits the constraints and checks a production vault would require.

## Vulnerabilities by category

| Category | Rules triggered |
|----------|----------------|
| Account validation | 001, 009 |
| PDA | 013 (×2), 014 |
| CPI | 017 |
| Math | 023, 025 |
| Auth / lifecycle | 030, 033, 034, 035 |
| Constraints | 043 |
| SPL Token | 044, 045 |
| Account lifecycle | 007, 010, 032 |

**Total: 18 distinct findings (4 Critical, 9 High, 5 Medium)**

See [EXPECTED_FINDINGS.md](./EXPECTED_FINDINGS.md) for the precise file:line mapping used as the CLI regression oracle.

## Running the audit

```bash
anchor-audit examples/01-vulnerable-vault --output VAULT_AUDIT.md --verbose
```

Findings should match [EXPECTED_FINDINGS.md](./EXPECTED_FINDINGS.md). The CLI exit code should be `1` (critical/high findings present).
