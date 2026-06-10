# Rule 008: Uninitialized Account Use

**Severity:** High
**Category:** Account validation

## Description
An account is read or written before its initialization is complete or verified. This includes deserializing accounts whose data is still all zeroes, trusting fields of an account that a separate "initialize" instruction was supposed to populate, and `zero`-copy patterns that skip an is-initialized flag. Zeroed bytes often deserialize into *valid-looking* defaults (authority = `Pubkey::default()`, amount = 0).

## Vulnerable pattern
```rust
pub fn withdraw(ctx: Context<Withdraw>) -> Result<()> {
    let vault = &ctx.accounts.vault;
    // If vault was never initialized, vault.authority == Pubkey::default()
    // and an attacker can satisfy this by passing the default pubkey path
    if vault.authority != ctx.accounts.authority.key() {
        return err!(ErrorCode::Unauthorized);
    }
    // ...
    Ok(())
}
```

## Why this is dangerous
An attacker sequences instructions so the consuming instruction runs against an account that exists (rent-funded, correct owner) but was never initialized, or races initialization in the same transaction. Default field values then pass or bypass checks — `Pubkey::default()` authorities, zero balances treated as "no debt", or flags that read as false.

## Fix pattern
```rust
#[account]
pub struct Vault {
    pub is_initialized: bool,
    pub authority: Pubkey,
}

// Anchor's Account<'info, Vault> already rejects accounts whose
// discriminator is unset (never went through `init`). For raw accounts:
require!(vault.is_initialized, ErrorCode::Uninitialized);
require_keys_neq!(vault.authority, Pubkey::default());
```
Use `#[account(zero)]` only for accounts being initialized *in this instruction*, never for accounts being consumed.

## Detection heuristic
- `AccountInfo`/`UncheckedAccount` data deserialized without a discriminator or `is_initialized` check
- Authority comparisons that would pass for `Pubkey::default()`
- `#[account(zero)]` on accounts that are read before being written
- Multi-step init flows (create, then configure) where step 2+ doesn't verify step 1 ran

## References
- Coral sealevel-attacks — 4-initialization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-initialization)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; closely related to reinitialization attacks (Rule 031), which have caused fund loss in unaudited programs.
