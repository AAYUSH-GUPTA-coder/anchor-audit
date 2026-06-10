# Rule 024: Token Amount Arithmetic Overflow

**Severity:** High
**Category:** Math

## Description
The same overflow/underflow risk as lamport math (Rule 023) applied to SPL token amounts, share calculations, reward accumulators, and any `u64`/`u128` balance the program tracks itself. Vaults that compute shares from deposits, AMMs that compute output amounts, and staking programs accumulating rewards all multiply and add large numbers; without checked arithmetic these wrap silently in release builds.

## Vulnerable pattern
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    // shares = amount * total_shares / total_assets
    // amount * total_shares overflows u64 for large inputs
    let shares = amount * vault.total_shares / vault.total_assets;
    vault.total_shares += shares;   // unchecked
    vault.total_assets += amount;   // unchecked
    ctx.accounts.user_position.shares += shares;
    Ok(())
}
```

## Why this is dangerous
An overflow in `amount * total_shares` wraps to a small number, minting too few or — combined with a wrapped denominator — too many shares, letting an attacker mint shares disproportionate to their deposit and then redeem more than they put in. Accumulator overflows can reset reward debt. The conservation invariant (shares ↔ assets) is broken.

## Fix pattern
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    let shares = (amount as u128)
        .checked_mul(vault.total_shares as u128).ok_or(ErrorCode::Overflow)?
        .checked_div(vault.total_assets as u128).ok_or(ErrorCode::DivByZero)?;
    let shares = u64::try_from(shares).map_err(|_| ErrorCode::Overflow)?;
    vault.total_shares = vault.total_shares.checked_add(shares).ok_or(ErrorCode::Overflow)?;
    vault.total_assets = vault.total_assets.checked_add(amount).ok_or(ErrorCode::Overflow)?;
    Ok(())
}
```

## Detection heuristic
- `*`, `+`, `-` on token-amount/share/reward fields instead of `checked_*` (or widening to `u128` for intermediates)
- Multiplications of two `u64` token amounts without widening
- Reward/index accumulators using unchecked `+=`
- Missing `overflow-checks = true` in release profile

## References
- Neodyme — Solana common pitfalls: integer overflow (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Sec3 — arithmetic safety in Solana programs (https://www.sec3.dev/blog)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
Share/asset arithmetic errors are a recurring root cause of vault and AMM exploits across DeFi; standard high-severity audit finding.
