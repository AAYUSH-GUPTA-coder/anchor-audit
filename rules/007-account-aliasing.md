# Rule 007: Account Aliasing (Duplicate Mutable Accounts)

**Severity:** High
**Category:** Account validation

## Description
An instruction takes two mutable accounts of the same type for two distinct logical roles (sender/receiver, position A/position B) but never checks that they are different accounts. Passing the *same* account for both roles makes the handler's reads and writes interleave on one underlying account, corrupting balance math — typically letting value be created or destroyed.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, Balance>,
    #[account(mut)]
    pub to: Account<'info, Balance>, // may be the same account as `from`
    pub authority: Signer<'info>,
}

pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
    ctx.accounts.from.amount -= amount;
    ctx.accounts.to.amount += amount; // overwrites the deduction when aliased
    Ok(())
}
```

## Why this is dangerous
With `from == to`, Anchor deserializes the account into two independent in-memory copies; the last one serialized on exit wins. In the pattern above the `to` copy never saw the deduction, so the attacker's balance is credited `amount` with no debit — free money on every call.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut)]
    pub from: Account<'info, Balance>,
    #[account(mut, constraint = to.key() != from.key() @ ErrorCode::DuplicateAccount)]
    pub to: Account<'info, Balance>,
    pub authority: Signer<'info>,
}
```

## Detection heuristic
- Two or more `#[account(mut)]` fields of the same account type in one context
- No `constraint = a.key() != b.key()` (or distinct PDA seeds) separating same-typed mutable accounts
- Handlers performing read-modify-write on both accounts (balances, counters, positions)

## References
- Coral sealevel-attacks — 6-duplicate-mutable-accounts (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/6-duplicate-mutable-accounts)
- Solana program security course — duplicate mutable accounts (https://solana.com/developers/courses/program-security/duplicate-mutable-accounts)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No public headline exploit; a standard critical finding in public audit reports for AMM/order-matching programs that move value between same-typed accounts.
