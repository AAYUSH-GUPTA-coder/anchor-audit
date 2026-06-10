# Rule 004: Account Substitution (Missing Data Matching)

**Severity:** High
**Category:** Account validation

## Description
Two or more accounts in an instruction are logically related (a user and their state account, a vault and its token account) but no constraint enforces that relationship. Each account may individually be valid — correct owner, correct type — yet belong to a different user or pool than intended. The attacker substitutes a *valid but wrong* account.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub user: Signer<'info>,
    // Valid UserState account — but nothing ties it to `user`
    #[account(mut)]
    pub user_state: Account<'info, UserState>,
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
}

pub fn claim_rewards(ctx: Context<ClaimRewards>) -> Result<()> {
    let amount = ctx.accounts.user_state.pending_rewards; // someone else's rewards
    // ... transfer to user
    Ok(())
}
```

## Why this is dangerous
The attacker signs with their own key but passes another user's `UserState` (or a state account from a different pool with a better exchange rate). All type and owner checks pass, and the attacker claims rewards, balances, or withdrawal rights that belong to someone else.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct ClaimRewards<'info> {
    pub user: Signer<'info>,
    #[account(mut, has_one = user)] // UserState.user must equal user.key()
    pub user_state: Account<'info, UserState>,
    #[account(mut, address = user_state.reward_vault)]
    pub reward_vault: Account<'info, TokenAccount>,
}
```

## Detection heuristic
- Multiple typed accounts in one context with no `has_one`, `constraint =`, `address =`, or shared PDA `seeds` linking them
- Handlers that index into one account using identity from another (user → user_state, pool → pool_vault) without an enforced link
- State structs that store related pubkeys (`user`, `mint`, `vault`) that are never compared against the passed accounts

## References
- Coral sealevel-attacks — 1-account-data-matching (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/1-account-data-matching)
- Solana program security course — account data matching (https://solana.com/developers/courses/program-security/account-data-matching)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
Cashio (March 2022, ~$48M) is the canonical case of an unvalidated account chain: a forged collateral chain passed individual checks but the links between accounts were never enforced end-to-end.
