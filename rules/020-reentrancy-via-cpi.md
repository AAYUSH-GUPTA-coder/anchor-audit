# Rule 020: Reentrancy via CPI

**Severity:** High
**Category:** CPI

## Description
Solana's runtime forbids a program from being re-entered while already on the call stack *except* through self-recursion, which mitigates classic EVM-style reentrancy. But a check-then-CPI-then-effect ordering is still dangerous: if a program reads state, performs a CPI into another program, and that program (or a later instruction in the same transaction) can alter the first program's accounts before the effect is written, invariants break. The safe discipline is checks-effects-interactions: update your own state *before* the external call.

## Vulnerable pattern
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(ctx.accounts.position.balance >= amount, ErrorCode::Insufficient);
    // Interaction BEFORE effect: transfer out first...
    token::transfer(/* vault -> user */, amount)?;
    // ...then decrement. If the CPI path can re-enter a sibling instruction
    // that also reads `balance`, the stale balance is double-spent.
    ctx.accounts.position.balance -= amount;
    Ok(())
}
```

## Why this is dangerous
A callback program, a Token-2022 transfer hook, or a crafted multi-instruction transaction can observe the un-decremented balance and act on it (withdraw again, use it as collateral) before the effect lands. Even without true reentrancy, doing effects after interactions widens the window for cross-instruction inconsistencies and partial-failure states.

## Fix pattern
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(ctx.accounts.position.balance >= amount, ErrorCode::Insufficient);
    // Effect first
    ctx.accounts.position.balance = ctx.accounts.position.balance
        .checked_sub(amount).ok_or(ErrorCode::Underflow)?;
    // Interaction last
    token::transfer(/* vault -> user */, amount)?;
    Ok(())
}
```
Be especially careful with Token-2022 transfer hooks, which run untrusted code during the transfer.

## Detection heuristic
- State mutations placed *after* CPIs that depend on the pre-CPI state (withdraw/transfer before decrement)
- CPIs into programs that can call back (transfer hooks, callback registries) mid-update
- Missing per-account "in progress"/lock flags around multi-step flows that span CPIs

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — checks-effects-interactions on Solana (https://www.sec3.dev/blog)
- Solana docs — CPI and call depth (https://solana.com/docs/core/cpi)

## Real-world exploits (if any)
No single attributed public Solana exploit (the runtime blocks the classic form); included because Token-2022 transfer hooks reintroduce callback-driven reentrancy surface.
