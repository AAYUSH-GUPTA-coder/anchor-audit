# Rule 016: Stored Bump Mismatch

**Severity:** Medium
**Category:** PDA

## Description
A program stores a PDA's bump at initialization and later re-derives the PDA, but the verification path doesn't actually pin the derivation to the stored bump — or stores the bump but then re-derives with `find_program_address` (recomputing the canonical bump) inconsistently across instructions. Inconsistent bump handling lets a non-canonical-bump PDA pass in one instruction and fail in another, or lets the wrong account satisfy a check.

## Vulnerable pattern
```rust
// init stores the canonical bump
ctx.accounts.state.bump = ctx.bumps.state;

// ...but a later instruction re-derives canonically and signs with that,
// ignoring the stored bump entirely:
let (pda, bump) = Pubkey::find_program_address(&[b"state", user.key().as_ref()], ctx.program_id);
let seeds = &[b"state", user.key().as_ref(), &[bump]];
// If the account was created with a different (non-canonical) bump,
// `pda` won't match the real account, or signing fails silently.
```

## Why this is dangerous
Mismatched bump sources cause CPI signing to use the wrong signer seeds (transactions fail, or worse, a different valid PDA is authorized), and address checks that should reject an account can pass when a non-canonical bump was stored. The inconsistency is the bug: every code path must use the same stored canonical bump.

## Fix pattern
```rust
// Store canonical bump once at init:
ctx.accounts.state.bump = ctx.bumps.state;

// Always reuse the stored bump for both constraints and signing:
#[account(seeds = [b"state", user.key().as_ref()], bump = state.bump)]
pub state: Account<'info, State>,

let seeds = &[b"state", user.key().as_ref(), &[ctx.accounts.state.bump]];
let signer = &[&seeds[..]];
```

## Detection heuristic
- A `bump` field stored at init but some instructions use `find_program_address` / `ctx.bumps` instead of the stored value
- `bump = state.bump` in some constraints and bare `bump` in others for the same PDA
- `invoke_signed` seeds whose bump source differs from the constraint's bump source

## References
- Anchor docs — bumps and seeds (https://www.anchor-lang.com/docs/account-constraints)
- Coral sealevel-attacks — 7-bump-seed-canonicalization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-bump-seed-canonicalization)
- Solana program security course — bump seed canonicalization (https://solana.com/developers/courses/program-security/bump-seed-canonicalization)

## Real-world exploits (if any)
No public attributed exploit; reported in audits as a consistency/correctness issue that can brick CPI-signing instructions.
