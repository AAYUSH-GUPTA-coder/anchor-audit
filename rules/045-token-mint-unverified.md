# Rule 045: Token Mint Unverified

**Severity:** High
**Category:** SPL Token

## Description
A token account is tied to exactly one mint, but code that accepts "a token account" without constraining its `mint` allows an attacker to pass an account for a *different*, worthless mint. The program credits or values the deposit as if it were the expected (valuable) token, because it never checked which token the account actually holds.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    // No check that user_token.mint == expected USDC mint
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // Transfers `amount` of WHATEVER mint user_token holds, credits as USDC
    token::transfer(/* user_token -> vault */, amount)?;
    ctx.accounts.position.usdc_balance += amount;
    Ok(())
}
```

## Why this is dangerous
The attacker mints a worthless token, deposits it, and is credited a USDC balance one-for-one, then withdraws real USDC. Without a mint check, the program cannot tell a valuable token from a fake one. The transfer must also target a vault of the *same* mint, or accounting diverges from the actual held assets.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub user: Signer<'info>,
    #[account(mut, token::mint = usdc_mint, token::authority = user)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut, token::mint = usdc_mint)]
    pub vault: Account<'info, TokenAccount>,
    #[account(address = config.usdc_mint)]
    pub usdc_mint: Account<'info, Mint>,
}
```

## Detection heuristic
- Token accounts used without a `token::mint = ...` constraint or `.mint` equality check
- Deposit/withdraw/swap logic that credits a specific asset from an unconstrained token account
- Vault and user token accounts not constrained to the *same* expected mint
- A `Mint` account referenced but never pinned via `address =` to the configured mint

## References
- anchor_spl docs — token::mint constraint (https://docs.rs/anchor-spl/latest/anchor_spl/)
- SPL Token docs — token account mint binding (https://spl.solana.com/token)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public headline exploit; missing mint validation is a recurring high/critical finding in audits of deposit-based DeFi programs.
