# Rule 043: `Account` vs `AccountInfo` Misuse

**Severity:** High
**Category:** Constraints

## Description
Choosing `AccountInfo<'info>` / `UncheckedAccount<'info>` where `Account<'info, T>` (or a typed wrapper like `Program`, `Signer`, `Sysvar`, `InterfaceAccount`) belongs throws away Anchor's automatic validation: owner check, discriminator check, and deserialization. Reaching for the untyped variant "to make it compile" silently disables the protections that prevent owner-spoofing (Rule 002) and type-cosplay (Rule 003).

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Use<'info> {
    /// CHECK: it's our config
    pub config: AccountInfo<'info>, // no owner/discriminator/type check
    pub user: Signer<'info>,
}

pub fn use_config(ctx: Context<Use>) -> Result<()> {
    let config = Config::try_from_slice(&ctx.accounts.config.data.borrow())?; // unsafe
    require_keys_eq!(config.admin, ctx.accounts.user.key());
    Ok(())
}
```

## Why this is dangerous
With `AccountInfo`, nothing verifies that `config` is owned by this program or is actually a `Config` — the attacker forges its bytes (Rule 002) or passes a different account type with a compatible layout (Rule 003). The single type choice is the difference between Anchor enforcing three invariants and the program enforcing none.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Use<'info> {
    // Account<'info, Config> checks owner == program ID, discriminator, and
    // deserializes safely.
    #[account(has_one = admin)]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
```
Reserve `AccountInfo`/`UncheckedAccount` for genuinely opaque accounts, and when used, document the manual checks in the `/// CHECK:` comment and perform them.

## Detection heuristic
- `AccountInfo`/`UncheckedAccount` whose data is deserialized into a known program type
- `/// CHECK:` comments that don't describe a real, performed validation
- Program/token/sysvar accounts typed as `AccountInfo` instead of `Program`/`Account<TokenAccount>`/`Sysvar`
- Typed wrappers avoided "to fix a lifetime/borrow error" without restoring the checks manually

## References
- Anchor docs — account types (https://www.anchor-lang.com/docs/account-types)
- The Anchor Book — AccountInfo and UncheckedAccount (https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed exploit for the type choice alone; it is the enabling mistake behind owner-check and type-cosplay exploits (Rules 002, 003) repeatedly flagged in audits.
