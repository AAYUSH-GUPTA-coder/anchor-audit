# Rule 003: Missing Discriminator Check (Type Cosplay)

**Severity:** High
**Category:** Account validation

## Description
Anchor prefixes every account with an 8-byte discriminator derived from the account type name, which distinguishes one account type from another at runtime. Code that deserializes account data manually — or uses types that skip the discriminator — allows an account of type A to be passed where type B is expected ("type cosplay"), as long as the byte layouts are compatible.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct AdminAction<'info> {
    /// CHECK: admin config
    pub admin_config: AccountInfo<'info>,
    pub admin: Signer<'info>,
}

pub fn admin_action(ctx: Context<AdminAction>) -> Result<()> {
    // UserAccount and AdminConfig are both { authority: Pubkey } —
    // raw deserialization cannot tell them apart
    let config = AdminConfig::try_from_slice(&ctx.accounts.admin_config.data.borrow())?;
    require_keys_eq!(config.authority, ctx.accounts.admin.key());
    Ok(())
}
```

## Why this is dangerous
An attacker initializes a low-privilege account type (e.g. their own `UserAccount`) whose layout matches the privileged type, then passes it where `AdminConfig` is expected. The deserialization succeeds with attacker-chosen field values, and the attacker passes authority checks meant for admins.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct AdminAction<'info> {
    // Account<'info, T> verifies the 8-byte discriminator and owner
    pub admin_config: Account<'info, AdminConfig>,
    pub admin: Signer<'info>,
}
```
In manual deserialization, compare the first 8 bytes against `AdminConfig::DISCRIMINATOR` before parsing.

## Detection heuristic
- Manual `try_from_slice` / borsh deserialization of full account data without slicing off and checking the first 8 bytes
- Account structs with identical or prefix-compatible field layouts used in the same program
- `#[account]` types deserialized through `AccountInfo` instead of `Account<'info, T>`
- Non-Anchor programs with multiple account types and no type/version tag byte

## References
- Coral sealevel-attacks — 3-type-cosplay (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/3-type-cosplay)
- Solana program security course — type cosplay (https://solana.com/developers/courses/program-security/type-cosplay)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No public headline exploit attributed solely to type cosplay; it is a recurring critical finding in public Sec3 and OtterSec audit reports of pre-launch programs.
