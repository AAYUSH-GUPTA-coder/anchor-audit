# Rule 027: Token Decimal Mismatch

**Severity:** Medium
**Category:** Math

## Description
Different SPL mints have different `decimals`. Code that compares, adds, or exchanges raw token amounts across mints without normalizing for decimals treats `1 USDC` (6 decimals → 1_000_000) and `1 of an 9-decimal token` (1_000_000_000) as if they were the same magnitude. Any cross-mint price, swap, or collateral computation that ignores decimals is wrong by orders of magnitude.

## Vulnerable pattern
```rust
// Collateral value compared directly to debt, different mints/decimals:
let collateral_amount = ctx.accounts.collateral_token.amount; // 9 decimals
let debt_amount = ctx.accounts.debt_token.amount;             // 6 decimals
require!(collateral_amount >= debt_amount, ErrorCode::Undercollateralized);
// 1.0 collateral (1e9) looks like 1000x the debt of 1.0 (1e6)
```

## Why this is dangerous
The attacker exploits the scale error in whichever direction helps them: borrowing against collateral that appears 1000x more valuable than it is, or swapping at a wildly mispriced rate. Hardcoding a decimal assumption (e.g. always 6) breaks the moment a mint with different decimals is used, which an attacker can arrange when mints are user-supplied.

## Fix pattern
```rust
// Normalize both sides to a common scale using each mint's decimals:
fn to_scaled(amount: u64, decimals: u8, target: u8) -> Option<u128> {
    let a = amount as u128;
    if decimals <= target {
        a.checked_mul(10u128.pow((target - decimals) as u32))
    } else {
        Some(a / 10u128.pow((decimals - target) as u32))
    }
}
let coll = to_scaled(collateral_amount, collateral_mint.decimals, 18)?;
let debt = to_scaled(debt_amount, debt_mint.decimals, 18)?;
require!(coll >= debt, ErrorCode::Undercollateralized);
```
Read `decimals` from the actual `Mint` account, never hardcode.

## Detection heuristic
- Cross-mint comparisons/arithmetic on raw `.amount` without reading each `Mint::decimals`
- Hardcoded decimal constants (e.g. `1_000_000`) instead of `mint.decimals`
- Price/collateral/swap math mixing amounts from different mints
- Mint accounts passed but `decimals` never read

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- SPL Token docs — mint decimals (https://spl.solana.com/token)
- Sec3 — token handling pitfalls (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; decimal-handling errors are a frequent audit finding in lending and DEX programs that support arbitrary mints.
