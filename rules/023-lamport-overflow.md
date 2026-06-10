# Rule 023: Lamport Arithmetic Overflow / Underflow

**Severity:** High
**Category:** Math

## Description
Lamport balances are `u64`. Adding to or subtracting from them with plain `+`/`-` (or `+=`/`-=`) risks wrapping: in release builds Rust arithmetic does not panic on overflow unless `overflow-checks` is enabled, so an underflow silently wraps to a huge number. Direct lamport manipulation via `try_borrow_mut_lamports` is especially exposed because it bypasses any token-program accounting.

## Vulnerable pattern
```rust
pub fn settle(ctx: Context<Settle>, fee: u64) -> Result<()> {
    let vault = ctx.accounts.vault.to_account_info();
    let user = ctx.accounts.user.to_account_info();
    // If fee > vault balance, this underflows and wraps to ~u64::MAX
    **vault.try_borrow_mut_lamports()? -= fee;
    **user.try_borrow_mut_lamports()? += fee;
    Ok(())
}
```

## Why this is dangerous
An underflow on the debit side wraps the vault's lamport field to an enormous value, and a paired credit can mint lamports out of nothing, breaking the transaction's lamport-conservation invariant (the runtime rejects unbalanced lamports, but intra-program accounting fields tracking "balance" can still be corrupted). Overflow on a credit can zero out a balance. Either way, accounting is falsified.

## Fix pattern
```rust
pub fn settle(ctx: Context<Settle>, fee: u64) -> Result<()> {
    let vault = ctx.accounts.vault.to_account_info();
    let user = ctx.accounts.user.to_account_info();
    let v = vault.lamports();
    **vault.try_borrow_mut_lamports()? = v.checked_sub(fee).ok_or(ErrorCode::Underflow)?;
    let u = user.lamports();
    **user.try_borrow_mut_lamports()? = u.checked_add(fee).ok_or(ErrorCode::Overflow)?;
    Ok(())
}
```
Also set `overflow-checks = true` in the program's release profile in `Cargo.toml`.

## Detection heuristic
- `try_borrow_mut_lamports` with `+=`/`-=`/`+`/`-` instead of `checked_add`/`checked_sub`
- Lamport math on `account.lamports()` without checked operations
- `Cargo.toml` profile missing `overflow-checks = true`
- Any `u64` balance field updated with unchecked arithmetic

## References
- Neodyme — Solana common pitfalls: integer overflow (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Solana program security course — overflow and underflow (https://solana.com/developers/courses/program-security)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
Unchecked arithmetic is a contributing factor in numerous DeFi accounting exploits; it is one of the most frequently flagged issues in public Solana audit reports.
