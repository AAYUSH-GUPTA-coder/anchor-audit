# Rule 030: Missing Authorization on Privileged Instruction

**Severity:** Critical
**Category:** Auth

## Description
A privileged instruction — withdraw, close, set-config, pause, mint, upgrade-authority change — performs its action without verifying that the caller is allowed to. This is broader than a missing signer (Rule 001): even with a signer present, the program may fail to check that the signer is *the right* principal for this resource (the vault's owner, the protocol admin, the position holder).

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub caller: Signer<'info>, // any signer at all
}

pub fn set_fee(ctx: Context<SetFee>, new_fee: u16) -> Result<()> {
    // No check that caller == config.admin
    ctx.accounts.config.fee_bps = new_fee;
    Ok(())
}
```

## Why this is dangerous
Anyone can sign a transaction, so requiring "a signer" without binding it to the privileged role lets any user set the protocol fee, withdraw from any vault, or change critical config. The attacker simply calls the instruction with their own signature. This is the most direct privilege-escalation class.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut, has_one = admin)] // config.admin must equal admin.key()
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
```
Use `has_one`, `address = config.admin`, or an explicit `require_keys_eq!(caller.key(), config.admin)` plus a signer requirement.

## Detection heuristic
- Privileged handlers (set_*, withdraw, close, mint, pause, transfer_authority) with a `Signer` that is never compared to a stored authority
- Missing `has_one` / `address =` / `require_keys_eq!` linking the signer to the resource's owner/admin
- Config or vault mutations where the only gate is "is a signer"
- Admin functions reachable by accounts with no role binding

## References
- Solana program security course — signer & owner authorization (https://solana.com/developers/courses/program-security/signer-auth)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Anchor docs — has_one and address constraints (https://www.anchor-lang.com/docs/account-constraints)

## Real-world exploits (if any)
Missing/weak authorization is among the most common root causes in public Solana exploit post-mortems and audit critical findings.
