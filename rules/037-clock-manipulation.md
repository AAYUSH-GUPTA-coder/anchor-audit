# Rule 037: Clock / Time-Based Logic Without Bounds

**Severity:** Medium
**Category:** Auth

## Description
Logic that depends on the Clock sysvar (`unix_timestamp` or `slot`) for vesting, auctions, cooldowns, TWAPs, or expiry must account for the fact that timestamps are validator-influenced and can drift, and that slot-to-time conversions are approximate. Using raw timestamps without sanity bounds, staleness checks, or monotonicity guards lets edge cases and minor manipulation skew time-sensitive outcomes.

## Vulnerable pattern
```rust
pub fn claim_vested(ctx: Context<Claim>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    // Assumes `now` is exact and strictly increasing; no bounds, no
    // check that start <= now, no guard against a recorded future time.
    let elapsed = now - ctx.accounts.vest.start_ts;
    let vested = ctx.accounts.vest.total * elapsed as u64 / ctx.accounts.vest.duration;
    // ...
    Ok(())
}
```

## Why this is dangerous
`unix_timestamp` can be slightly ahead of or behind real time and is not guaranteed strictly monotonic across the boundary cases the program may assume. If `now < start_ts`, `elapsed` underflows (Rule 023); unbounded `elapsed` can over-vest. For oracle/auction logic, even small timestamp influence lets a validator-adjacent actor nudge outcomes. Relying on time for high-value, fine-grained decisions is fragile.

## Fix pattern
```rust
pub fn claim_vested(ctx: Context<Claim>) -> Result<()> {
    let now = Clock::get()?.unix_timestamp;
    let v = &ctx.accounts.vest;
    require!(now >= v.start_ts, ErrorCode::NotStarted);
    let elapsed = (now - v.start_ts).min(v.duration as i64) as u64; // clamp
    let vested = (v.total as u128)
        .checked_mul(elapsed as u128).ok_or(ErrorCode::Overflow)?
        .checked_div(v.duration as u128).ok_or(ErrorCode::DivByZero)? as u64;
    // ...
    Ok(())
}
```
Clamp ranges, reject out-of-order timestamps, and avoid time as the sole gate for high-value actions.

## Detection heuristic
- `Clock::get()?.unix_timestamp` / `slot` used in subtraction without a `now >= start` guard (underflow risk)
- Time deltas not clamped to a maximum (over-vesting / over-accrual)
- Slot-count used as wall-clock time via a hardcoded slot duration
- Auction/oracle/expiry decisions gated solely on validator-influenced time

## References
- Solana docs — Clock sysvar and timestamp semantics (https://docs.solanalabs.com/runtime/sysvars#clock)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — time-based logic pitfalls (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public Solana exploit; time-handling issues are recurring medium audit findings in vesting, auction, and oracle code.
