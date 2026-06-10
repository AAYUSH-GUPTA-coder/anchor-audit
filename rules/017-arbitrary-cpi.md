# Rule 017: Arbitrary CPI (Unvalidated Target Program)

**Severity:** Critical
**Category:** CPI

## Description
A program performs a cross-program invocation to a program whose ID comes from a passed-in account, without verifying it against the expected program ID. The attacker supplies their own malicious program in place of the intended one (e.g. a fake "token program"), and the CPI executes attacker code with whatever accounts and signer seeds the calling program provides.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    pub token_program: AccountInfo<'info>, // unvalidated
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    let ix = /* build a transfer ix targeting ctx.accounts.token_program.key() */;
    invoke(&ix, &[/* accounts */])?; // calls whatever program was passed
    Ok(())
}
```

## Why this is dangerous
The attacker passes a program they control as `token_program`. Instead of transferring tokens, the fake program does nothing (so the caller believes a transfer happened) or manipulates the accounts it was handed. When the calling program signs the CPI with a PDA, the attacker's program inherits that PDA's authority for the duration of the call.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    pub token_program: Program<'info, Token>, // Anchor verifies the ID
    #[account(mut)]
    pub from: Account<'info, TokenAccount>,
    #[account(mut)]
    pub to: Account<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
// Or, for raw AccountInfo: require_keys_eq!(token_program.key(), expected::ID);
```

## Detection heuristic
- CPI target programs typed as `AccountInfo`/`UncheckedAccount` rather than `Program<'info, T>`
- `invoke` / `invoke_signed` where the target program ID is read from accounts without a preceding `require_keys_eq!` against a known ID
- Program IDs taken from instruction data or config accounts that are themselves attacker-controllable

## References
- Coral sealevel-attacks — 5-arbitrary-cpi (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-arbitrary-cpi)
- Solana program security course — arbitrary CPI (https://solana.com/developers/courses/program-security/arbitrary-cpi)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public headline exploit; arbitrary-CPI is one of the most common critical findings across public Solana audit reports.
