# Rule 025: Precision Loss (Division Before Multiplication)

**Severity:** Medium
**Category:** Math

## Description
Integer division truncates. Performing division before multiplication discards the remainder early, magnifying rounding error in the final result. The canonical bug is `(a / b) * c` where `a / b` rounds to zero or loses significant digits before being scaled up, instead of `(a * c) / b`, which preserves precision by dividing last.

## Vulnerable pattern
```rust
// reward = stake / total_stake * reward_pool
// stake / total_stake is integer division: for any stake < total_stake
// it evaluates to 0, so reward is always 0.
let reward = (stake / total_stake) * reward_pool;
```

## Why this is dangerous
A user with 1 of 1000 total stake computes `1 / 1000 = 0`, then `0 * reward_pool = 0` — they earn nothing, while the rounding "dust" silently accrues somewhere or is lost. In fee or exchange-rate math, the same error lets an attacker structure amounts so the protocol rounds in their favor repeatedly, extracting value over many small transactions.

## Fix pattern
```rust
// Multiply first, divide last, and widen to u128 to avoid overflow:
let reward = (stake as u128)
    .checked_mul(reward_pool as u128).ok_or(ErrorCode::Overflow)?
    .checked_div(total_stake as u128).ok_or(ErrorCode::DivByZero)?;
let reward = u64::try_from(reward).map_err(|_| ErrorCode::Overflow)?;
```
Where exactness matters, track and distribute remainders explicitly.

## Detection heuristic
- Expressions of the form `(a / b) * c` or `a / b * c` on token/share/fee amounts
- Division applied to operands that are then scaled up
- Ratio/rate math done entirely in `u64` without widening to `u128`
- Reward-per-share or price calculations dividing before applying a multiplier

## References
- Sec3 — arithmetic precision in Solana programs (https://www.sec3.dev/blog)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public exploit; precision-loss findings are common in audits of staking and AMM math and can leak value continuously.
