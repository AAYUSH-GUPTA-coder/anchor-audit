# Rule 040: `realloc` Without Zero-Init

**Severity:** Medium
**Category:** Constraints

## Description
When an account is grown with `realloc`, the newly added bytes are not automatically zeroed unless zero-init is requested. If `realloc(..., zero_init = false)` is used to *increase* size, the new region may contain leftover data from a previous, larger allocation of that memory, which then deserializes into account fields as garbage or attacker-influenced values.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Grow<'info> {
    #[account(
        mut,
        realloc = 8 + NewLayout::INIT_SPACE, // larger than before
        realloc::payer = payer,
        realloc::zero = false, // new bytes NOT zeroed
    )]
    pub state: Account<'info, NewLayout>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## Why this is dangerous
The new tail bytes can hold stale contents (from prior data at that memory, or non-deterministic leftovers), so newly-added fields deserialize to nonzero, unexpected values instead of clean defaults. Logic that assumes appended fields start at zero (counters, flags, balances) is then wrong from the first read, which an attacker may be able to steer.

## Fix pattern
```rust
#[account(
    mut,
    realloc = 8 + NewLayout::INIT_SPACE,
    realloc::payer = payer,
    realloc::zero = true, // zero the newly-added bytes when growing
)]
pub state: Account<'info, NewLayout>,
```
Use `realloc::zero = true` whenever increasing size; `false` is only safe when shrinking or immediately overwriting the entire new region.

## Detection heuristic
- `realloc::zero = false` (or the raw `AccountInfo::realloc(new_len, false)`) on size *increases*
- New fields appended via realloc that are read before being explicitly written
- Manual `realloc` calls that don't memset the grown region to zero
- Growth paths assuming default (zero) values for newly-added fields

## References
- Anchor docs — realloc constraint (https://www.anchor-lang.com/docs/account-constraints)
- Solana docs — AccountInfo::realloc semantics (https://docs.rs/solana-program/latest/solana_program/account_info/struct.AccountInfo.html#method.realloc)
- Sec3 — realloc safety (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; non-zeroed realloc is a documented medium audit finding for programs that grow accounts over time.
