# Rule 039: Constraint Evaluation Stage (Pre- vs Post-State)

**Severity:** Medium
**Category:** Constraints

## Description
Anchor evaluates account constraints during account validation, before the instruction handler body runs. A `constraint = ...` expression therefore sees the *pre-handler* state of the accounts. Developers sometimes write constraints expecting them to hold after the handler mutates state, or place a critical invariant only in a constraint that is checked too early, leaving a window where the post-state violates the intended invariant.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // Evaluated BEFORE the handler runs, so it validates the OLD balance,
    // not the balance after the withdrawal. It does not guarantee the
    // post-withdraw invariant the author intended.
    #[account(mut, constraint = vault.balance >= MIN_RESERVE @ ErrorCode::ReserveBreached)]
    pub vault: Account<'info, Vault>,
    // ...
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance -= amount; // post-state never re-checked
    Ok(())
}
```

## Why this is dangerous
The reserve check passes against the pre-withdrawal balance, then the handler withdraws an amount that breaches the reserve — the invariant the constraint was meant to protect is violated after the fact. Relying on a pre-state constraint to guard a post-state property is a logic gap an attacker exercises by choosing `amount` to slip through the early check.

## Fix pattern
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    vault.balance = vault.balance.checked_sub(amount).ok_or(ErrorCode::Underflow)?;
    // Re-check the invariant against POST-state, in the handler:
    require!(vault.balance >= MIN_RESERVE, ErrorCode::ReserveBreached);
    Ok(())
}
```
Use constraints for pre-conditions; assert post-conditions explicitly in the handler.

## Detection heuristic
- `constraint = ...` expressions that reference balances/state the same handler mutates, intended as post-conditions
- Invariants present only as account constraints but not re-asserted after mutation
- Handlers that change a value a constraint depends on, with no post-mutation `require!`
- Comments implying "after" semantics on a constraint (which always runs "before")

## References
- Anchor docs — constraint evaluation order (https://www.anchor-lang.com/docs/account-constraints)
- The Anchor Book — constraints (https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html)
- Sec3 — Anchor constraint pitfalls (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; pre/post-state confusion is a subtle logic finding that appears in audits of programs with reserve/ratio invariants.
