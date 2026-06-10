# Rule 002: Missing Owner Check

**Severity:** Critical
**Category:** Account validation

## Description
An account is read or trusted without verifying which program owns it. On Solana, only an account's owner program can modify its data, but *anyone* can create an account with arbitrary contents owned by a different program (or the System Program) and pass it into your instruction. If the program deserializes account data without an owner check, an attacker can substitute a forged account with attacker-chosen field values.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: config account
    pub config: AccountInfo<'info>,
    pub admin: Signer<'info>,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Deserializes raw bytes — never checks config.owner
    let config = Config::try_from_slice(&ctx.accounts.config.data.borrow())?;
    require_keys_eq!(config.admin, ctx.accounts.admin.key());
    // ... transfer `amount` out
    Ok(())
}
```

## Why this is dangerous
The attacker creates their own account with the same byte layout as `Config`, sets `admin` to their own key, and passes it in. The deserialization succeeds, the admin check passes against the forged data, and the attacker withdraws funds. Every field read from an unverified account is attacker-controlled.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Account<'info, T> verifies owner == crate::ID and the discriminator
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
```
For accounts owned by another program, constrain explicitly: `#[account(owner = other_program::ID)]`.

## Detection heuristic
- `AccountInfo` / `UncheckedAccount` whose `.data` is borrowed and deserialized (`try_from_slice`, `AnchorDeserialize`, manual byte slicing)
- No `owner =` constraint and no `require_keys_eq!(account.owner, ...)` before trusting the data
- `/// CHECK:` comments that do not explain a real validation performed elsewhere
- Raw-Solana handlers missing `if account.owner != program_id` before reads

## References
- Neodyme — Solana common pitfalls: missing ownership check (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Coral sealevel-attacks — 2-owner-checks (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/2-owner-checks)
- Solana program security course — owner checks (https://solana.com/developers/courses/program-security/owner-checks)

## Real-world exploits (if any)
Crema Finance (July 2022, ~$8.8M): the attacker supplied a forged tick account that the program trusted without adequate validation of its provenance, enabling fee data manipulation and flash-loan-funded drains.
