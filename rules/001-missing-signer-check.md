# Rule 001: Missing Signer Check

**Severity:** Critical
**Category:** Account validation

## Description
An instruction that performs a privileged action (changing an authority, moving funds, mutating user state) accepts the relevant authority account without requiring its signature. Comparing the account's public key against a stored authority proves the *address* matches, but not that the holder of that key approved the transaction — anyone can pass any public key as a read-only account.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct UpdateAuthority<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    /// CHECK: current vault authority
    pub authority: AccountInfo<'info>,
}

pub fn update_authority(ctx: Context<UpdateAuthority>, new_authority: Pubkey) -> Result<()> {
    // Key equality only — no signature required
    require_keys_eq!(ctx.accounts.vault.authority, ctx.accounts.authority.key());
    ctx.accounts.vault.authority = new_authority;
    Ok(())
}
```

## Why this is dangerous
An attacker submits the transaction themselves, passing the legitimate authority's public key as the `authority` account without its signature. The key-equality check passes, and the attacker rotates the vault authority to a key they control, then drains the vault through legitimate paths. This is the single most common Solana vulnerability class.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct UpdateAuthority<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>, // Anchor enforces is_signer
}

pub fn update_authority(ctx: Context<UpdateAuthority>, new_authority: Pubkey) -> Result<()> {
    ctx.accounts.vault.authority = new_authority;
    Ok(())
}
```

## Detection heuristic
- Accounts named `authority`, `admin`, `owner`, `signer`, `user`, or `payer` typed as `AccountInfo` or `UncheckedAccount` instead of `Signer`
- Handlers that mutate state or move lamports/tokens where no account in the context is a `Signer`
- Key comparisons (`require_keys_eq!`, `==` on `key()`) against a stored authority with no accompanying signature requirement
- In non-Anchor code paths: missing `if !account.is_signer { return Err(...) }`

## References
- Neodyme — Solana common pitfalls: missing signer check (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Coral sealevel-attacks — 0-signer-authorization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/0-signer-authorization)
- Solana program security course — signer authorization (https://solana.com/developers/courses/program-security/signer-auth)

## Real-world exploits (if any)
No single headline exploit; missing signer checks appear repeatedly in public audit reports (OtterSec, Neodyme, Sec3) as critical findings caught pre-deployment.
