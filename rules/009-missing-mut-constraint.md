# Rule 009: Missing `mut` Constraint

**Severity:** Medium
**Category:** Account validation

## Description
A handler modifies an account's data or lamports, but the account is not declared `#[account(mut)]`. Anchor only persists changes for accounts marked writable; without `mut`, the runtime either rejects the transaction (for lamport changes) or silently discards data mutations at serialization time, depending on the access path. Logic that *appears* to update state — debiting a balance, flipping a flag — leaves on-chain state untouched.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct RecordDebt<'info> {
    pub user_state: Account<'info, UserState>, // missing #[account(mut)]
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}

pub fn borrow(ctx: Context<RecordDebt>, amount: u64) -> Result<()> {
    ctx.accounts.user_state.debt += amount; // never persisted
    ctx.accounts.vault.balance -= amount;   // persisted — funds leave
    Ok(())
}
```

## Why this is dangerous
The asymmetry is the exploit: the value-moving side persists while the bookkeeping side does not. In the example, a user borrows repeatedly and their recorded debt stays at zero — the protocol pays out with no liability recorded. Even when the failure mode is a transaction error, it can brick critical paths like liquidations.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct RecordDebt<'info> {
    #[account(mut, has_one = user)]
    pub user_state: Account<'info, UserState>,
    #[account(mut)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
```

## Detection heuristic
- Handler assigns to fields of an account (`ctx.accounts.x.field = ...`, `+=`, `-=`) whose struct field lacks `#[account(mut)]`
- Lamport mutation (`try_borrow_mut_lamports`) on non-`mut` accounts
- Pairs of accounts where one side of a balanced operation is `mut` and the other is not

## References
- Anchor docs — account constraints (https://www.anchor-lang.com/docs/account-constraints)
- The Anchor Book — the Accounts struct (https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No public exploit attributed; typically caught as a correctness bug in audits because it makes state updates silently no-op.
