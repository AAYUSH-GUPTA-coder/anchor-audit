# Expected Findings — `01-vulnerable-vault`

This document is the regression oracle for `anchor-audit`. When the CLI is run against
`examples/01-vulnerable-vault/`, it must produce at least the findings listed below.
All 18 findings trigger across 7 rule categories.

Source file: `programs/vulnerable_vault/src/lib.rs`

---

## Summary

| Severity | Count |
|----------|-------|
| Critical | 4 |
| High     | 9 |
| Medium   | 5 |
| Total    | 18 |

---

## Findings

### [CRITICAL] Rule 030 — Missing authorization on `set_admin`

**File:** `programs/vulnerable_vault/src/lib.rs:185–189` (SetAdmin context)
**Handler:** `set_admin` (line 38)

`SetAdmin` requires `caller: Signer<'info>` but never checks that `caller.key() == vault_state.admin`. Any wallet can call `set_admin` and rotate the protocol admin to themselves, gaining full administrative control.

---

### [CRITICAL] Rule 001 — Missing signer check tied to admin role in `set_admin`

**File:** `programs/vulnerable_vault/src/lib.rs:185–189` (SetAdmin context)
**Handler:** `set_admin` (line 39)

Same instruction as above: `caller` proves *a* signer but the program never binds it to the stored admin authority. The constraint `#[account(address = vault_state.admin)]` or `has_one = caller` is absent.

---

### [CRITICAL] Rule 017 — Arbitrary CPI: `token_program` unvalidated in `deposit`

**File:** `programs/vulnerable_vault/src/lib.rs:218`
**Handler:** `deposit` (line 63)

`token_program` is declared `AccountInfo<'info>` with a `/// CHECK:` comment but no `address =` constraint and no `Program<'info, Token>` type. An attacker passes a fake program; the CPI targets it instead of SPL Token, and the deposit "succeeds" (from the vault's perspective) while no real tokens move.

---

### [CRITICAL] Rule 033 — `init_if_needed` allows vault re-initialization

**File:** `programs/vulnerable_vault/src/lib.rs:172` (`init_if_needed` in InitializeVault)
**Handler:** `initialize_vault` (line 20)

`vault_state` uses `init_if_needed`. On a second call against an already-existing vault the handler body runs again unconditionally, overwriting `vault.admin`, `vault.fee_bps`, and `vault.vault_bump` with attacker-supplied values — a full re-initialization takeover.

---

### [HIGH] Rule 013 — Non-canonical bump accepted in `create_position`

**File:** `programs/vulnerable_vault/src/lib.rs:192` (`#[instruction(bump: u8)]`) and line 51 (`pos.bump = bump`)
**Handler:** `create_position` (line 46)

The `bump` argument comes from instruction data and is stored directly without verifying it equals the canonical bump returned by `find_program_address`. An attacker can supply a non-canonical bump that still satisfies `create_program_address`, creating multiple valid position PDAs for the same user — defeating one-position-per-user uniqueness guarantees (e.g. to double-claim).

---

### [HIGH] Rule 013 — Non-canonical bump stored from args in `initialize_vault`

**File:** `programs/vulnerable_vault/src/lib.rs:24` (parameter `vault_bump: u8`) and line 32 (`vault.vault_bump = vault_bump`)
**Handler:** `initialize_vault` (line 20)

`vault_bump` is caller-supplied and stored without canonical-bump verification. Later instructions derive the vault PDA using this stored bump; if it's non-canonical, the PDA derivation in e.g. `withdraw`'s signing seeds may target a different address than the `init_if_needed`-created account, breaking CPI authorization.

---

### [HIGH] Rule 014 — Predictable / permissionlessly-creatable user PDA

**File:** `programs/vulnerable_vault/src/lib.rs:193–205` (CreatePosition context)
**Handler:** `create_position` (line 46)

The user position PDA is derived from `[b"position", user.key()]` with `init` and no privilege gate beyond the user being a signer. Any party can create a position *for any user address* (including an address whose key they want to pre-empt) and seed it with attacker-chosen state before the legitimate user arrives.

---

### [HIGH] Rule 044 — Token account owner unverified in `deposit`

**File:** `programs/vulnerable_vault/src/lib.rs:211` (`pub user_token: Account<'info, TokenAccount>` in Deposit)
**Handler:** `deposit` (line 65)

`user_token` has no `token::authority = user` constraint. An attacker passes a token account owned by a different wallet. Because Anchor doesn't verify the authority, the CPI transfer may fail (token program rejects it) or, if the vault's own PDA accidentally matches, succeed while crediting the attacker for funds they didn't move.

---

### [HIGH] Rule 045 — Token mint unverified in `deposit`

**File:** `programs/vulnerable_vault/src/lib.rs:211` (Deposit context) and line 215 (vault_token)
**Handler:** `deposit` (line 62)

Neither `user_token` nor `vault_token` has a `token::mint = ...` constraint. An attacker deposits a worthless SPL token (or a different supported token) and the vault credits `deposited` as if it were the expected asset. The vault's accounting is then backed by the wrong token mint.

---

### [HIGH] Rule 034 — Missing `has_one`: position owner not verified in `withdraw`

**File:** `programs/vulnerable_vault/src/lib.rs:225–226` (Withdraw context)
**Handler:** `withdraw` (line 80)

`user_position` is typed `Account<'info, UserPosition>` but carries no `has_one = user` constraint. Any signer can pass *any* position account and withdraw from it, regardless of who originally deposited. An attacker drains all user positions.

---

### [HIGH] Rule 043 — `AccountInfo` misuse: `vault_state` untyped in `collect_fees`

**File:** `programs/vulnerable_vault/src/lib.rs:241`
**Handler:** `collect_fees` (line 110)

`vault_state` is `AccountInfo<'info>` with `/// CHECK:`. Anchor skips owner and discriminator validation entirely. An attacker passes a forged account with crafted bytes; the raw `vault_data[42]` read extracts an attacker-chosen bump, letting them sign with a PDA derived from that bump and drain any vault token account the authority controls.

---

### [HIGH] Rule 007 — Account aliasing: `vault_token` and `fee_recipient` can be the same

**File:** `programs/vulnerable_vault/src/lib.rs:243–245` (CollectFees context)
**Handler:** `collect_fees` (line 110)

`vault_token` and `fee_recipient` are both `#[account(mut)]` with no uniqueness constraint. When they alias, Anchor deserializes the same account into two in-memory copies; the last-written copy wins, producing wrong token balances. In this CPI context the behavior is the token program's to determine, but the accounting invariant is broken.

---

### [HIGH] Rule 032 / Rule 010 — Closed-account revival: `close_position` leaves data intact

**File:** `programs/vulnerable_vault/src/lib.rs:133–136`
**Handler:** `close_position` (line 132)

Lamports are drained but the account data (including `deposited`, `owner`) is never zeroed and `CLOSED_ACCOUNT_DISCRIMINATOR` is never written. Within the same transaction, an attacker re-funds the account to prevent garbage collection and reuses the stale position state in a subsequent instruction (e.g. calling `withdraw` against the "closed" position).

---

### [MEDIUM] Rule 025 — Precision loss: division before multiplication in fee calc

**File:** `programs/vulnerable_vault/src/lib.rs:87`
**Handler:** `withdraw` (line 80)

```rust
let fee = amount / FEE_DENOMINATOR * vault_fee_bps as u64;
```

Integer division truncates before multiplying. For any `amount < FEE_DENOMINATOR` (< 10 000 tokens at base units) the fee evaluates to zero regardless of `fee_bps`. An attacker structures withdrawals in amounts below this threshold to drain the vault fee-free. Fix: `amount * fee_bps as u64 / FEE_DENOMINATOR` (multiply first).

---

### [MEDIUM] Rule 023 — Unchecked arithmetic: `pos.deposited -= amount`

**File:** `programs/vulnerable_vault/src/lib.rs:90`
**Handler:** `withdraw` (line 80)

The subtraction `pos.deposited -= amount` is unchecked. While a `require!` on line 85 guards against underflow from a single call, a concurrent instruction in the same transaction (or a race in a multi-instruction flow) can reduce `deposited` below `amount` after the check passes. Without `checked_sub`, the field wraps silently in release builds if `overflow-checks` is not set.

---

### [MEDIUM] Rule 009 — Missing `mut` constraint: `user_position` writes discarded in `deposit`

**File:** `programs/vulnerable_vault/src/lib.rs:211`
**Handler:** `deposit` (line 74)

```rust
pub user_position: Account<'info, UserPosition>,  // no #[account(mut)]
```

The handler writes `ctx.accounts.user_position.deposited += amount` (line 74) but `user_position` is not `mut`, so Anchor does not persist the change. Deposits appear to succeed (the token transfer completes), but `deposited` stays at zero forever — the vault's liability ledger is never updated.

---

### [MEDIUM] Rule 035 — Single-step admin transfer in `set_admin`

**File:** `programs/vulnerable_vault/src/lib.rs:38–40`
**Handler:** `set_admin`

`vault_state.admin` is overwritten in a single step with no `pending_admin` handshake. If `new_admin` is a mistyped address, a burn address, or an account the recipient cannot sign with, admin control is permanently lost with no recovery path.

---
