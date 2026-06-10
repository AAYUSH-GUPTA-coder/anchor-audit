# Rule 022: CPI Invoked with Attacker-Controlled Accounts

**Severity:** High
**Category:** CPI

## Description
A program performs a CPI to a trusted program but forwards accounts that the caller chose, without validating that those accounts are the correct ones for the operation. The target program ID is right, yet the *accounts* passed into it (source token account, destination, mint, authority) are attacker-substituted, so the trusted CPI executes against the wrong assets.

## Vulnerable pattern
```rust
pub fn payout(ctx: Context<Payout>, amount: u64) -> Result<()> {
    // token_program is correctly the SPL Token program, but `from` is
    // whatever token account the caller supplied — including the protocol
    // treasury — and the PDA authority signs for it.
    let seeds = &[b"vault_auth", &[ctx.accounts.config.bump]];
    token::transfer(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.from.to_account_info(),       // unvalidated
                to: ctx.accounts.to.to_account_info(),           // unvalidated
                authority: ctx.accounts.vault_auth.to_account_info(),
            },
            &[&seeds[..]],
        ),
        amount,
    )?;
    Ok(())
}
```

## Why this is dangerous
Because the program's PDA signs the transfer, it authorizes movement from whatever `from` account is supplied. The attacker points `from` at a token account the PDA controls (or `to` at their own wallet) and drains it through an otherwise-legitimate, correctly-targeted token CPI. The program ID check alone is insufficient — the accounts must be pinned too.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Payout<'info> {
    #[account(mut, address = config.vault_token)] // pin the source
    pub from: Account<'info, TokenAccount>,
    #[account(mut, token::mint = config.mint, token::authority = recipient)]
    pub to: Account<'info, TokenAccount>,
    // ...
}
```

## Detection heuristic
- CPIs whose account fields (`from`, `to`, `mint`, `authority`) are `AccountInfo`/`Account` with no `address =`, `token::*`, `has_one`, or seed binding
- A PDA signer used in a CPI where the source account is not constrained to the PDA-owned account
- `remaining_accounts` forwarded into CPIs without validation

## References
- Coral sealevel-attacks — 5-arbitrary-cpi (account-level variant) (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-arbitrary-cpi)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- anchor_spl docs — token constraints (https://docs.rs/anchor-spl/latest/anchor_spl/)

## Real-world exploits (if any)
No single attributed public exploit; unconstrained CPI accounts are a frequent critical/high finding in public audits of vault and payout programs.
