# Rule 036: Missing Pause / Freeze Guards

**Severity:** Low
**Category:** Auth

## Description
Critical value-moving instructions (deposit, withdraw, swap, borrow) have no mechanism to be paused or frozen in an emergency. When a vulnerability or anomaly is detected in production, the team has no way to halt the affected paths short of an upgrade, which takes time and may not be possible if the program is immutable. A pause flag, gated to an admin/guardian, is a standard defense-in-depth control.

## Vulnerable pattern
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // No pause check anywhere in the program; if an exploit is live,
    // there is no way to stop withdrawals while a fix is prepared.
    transfer_out(ctx, amount)
}
```

## Why this is dangerous
Lacking a circuit breaker turns a contained incident into a full drain: once exploitation begins, the team can only watch until an upgrade lands (and immutable programs can't even do that). A pause/freeze guard buys time to investigate, patch, and protect remaining funds. Its absence is a missing safety control rather than an exploitable bug by itself.

## Fix pattern
```rust
#[account]
pub struct Config { pub admin: Pubkey, pub paused: bool /* ... */ }

pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
    ctx.accounts.config.paused = paused; // admin/guardian gated
    Ok(())
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    require!(!ctx.accounts.config.paused, ErrorCode::Paused);
    transfer_out(ctx, amount)
}
```
Consider granular pausing (per-instruction) and a separate, fast-acting guardian role.

## Detection heuristic
- No `paused`/`frozen` field on the program's config/global state
- Value-moving instructions with no `require!(!config.paused, ...)` guard
- No admin/guardian instruction to toggle a pause
- Immutable programs (upgrade authority burned) with no in-program emergency stop

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — emergency controls and circuit breakers (https://www.sec3.dev/blog)
- Solana program security best practices (https://solana.com/developers/courses/program-security)

## Real-world exploits (if any)
No exploit caused by this directly; in numerous incidents the absence of a pause turned a detectable exploit into a total loss. Common informational/low audit recommendation.
