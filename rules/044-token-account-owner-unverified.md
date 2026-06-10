# Rule 044: Token Account Owner Unverified

**Severity:** High
**Category:** SPL Token

## Description
An SPL token account has an `owner` field (the wallet/PDA authority that controls it) distinct from the account's program owner. Code that accepts a token account and acts on it — crediting a user, treating it as a vault — without verifying its `owner` matches the expected authority lets an attacker pass a token account controlled by someone else, or by the program when it shouldn't be.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Stake<'info> {
    pub user: Signer<'info>,
    // No check that user_token.owner == user.key()
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
}

pub fn stake(ctx: Context<Stake>, amount: u64) -> Result<()> {
    // Credits the signer based on a token account they may not own
    ctx.accounts.stake_account.staked += amount;
    Ok(())
}
```

## Why this is dangerous
The attacker references a token account they don't control (or whose balance they can't actually move) to claim staking credit, or substitutes the program's own vault as the "source" to get credited without depositing. The token account's `owner`/`authority` must be tied to the principal the instruction credits or debits.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Stake<'info> {
    pub user: Signer<'info>,
    #[account(mut, token::authority = user)] // owner must be `user`
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut, has_one = user)]
    pub stake_account: Account<'info, StakeAccount>,
}
```
Use `token::authority = ...` (or check `token_account.owner == expected`) on every token account whose control matters.

## Detection heuristic
- `Account<'info, TokenAccount>` used in logic without `token::authority` / an `owner` equality check
- Crediting/debiting a principal based on a token account not constrained to that principal
- Vault/source token accounts not pinned via `token::authority = <pda>` or `address =`
- `.owner` of a token account read but compared to nothing

## References
- anchor_spl docs — token::authority constraint (https://docs.rs/anchor-spl/latest/anchor_spl/)
- SPL Token docs — account owner vs authority (https://spl.solana.com/token)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public headline exploit; unverified token-account ownership is a frequent high-severity audit finding in staking and vault programs.
