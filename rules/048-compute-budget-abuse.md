# Rule 048: Compute Budget Abuse (Unbounded Work)

**Severity:** Medium
**Category:** Runtime

## Description
Each Solana transaction has a compute-unit budget. An instruction that iterates over an attacker-controllable, unbounded collection — `remaining_accounts`, a `Vec` field that can grow without limit, or a loop whose count comes from input — can be pushed to exceed the budget and fail. If a critical operation (liquidation, settlement, crank) lives behind such a loop, the attacker grows the data until the operation can no longer complete, a denial-of-service.

## Vulnerable pattern
```rust
pub fn distribute(ctx: Context<Distribute>) -> Result<()> {
    // `holders` can grow unboundedly as users join; eventually this loop
    // exceeds the compute budget and every distribute() call fails.
    for holder in ctx.accounts.registry.holders.iter() {
        pay(holder)?;
    }
    Ok(())
}
```

## Why this is dangerous
Once the collection is large enough, the instruction always runs out of compute and reverts, permanently bricking the path. If liquidations or withdrawals depend on it, funds can be frozen. An attacker may intentionally inflate the collection (cheap entries) to trigger the DoS, or simply rely on organic growth crossing the limit.

## Fix pattern
```rust
// Paginate / bound the work per call, tracking progress in state:
pub fn distribute(ctx: Context<Distribute>, start: u32, count: u32) -> Result<()> {
    require!(count <= MAX_PER_CALL, ErrorCode::BatchTooLarge);
    let end = (start + count).min(ctx.accounts.registry.holders.len() as u32);
    for i in start..end {
        pay(&ctx.accounts.registry.holders[i as usize])?;
    }
    ctx.accounts.registry.cursor = end;
    Ok(())
}
```
Cap collection sizes at insertion and design cranks to process bounded batches.

## Detection heuristic
- Loops over `remaining_accounts`, `Vec`/`String` fields, or input-controlled counts with no per-call cap
- Account structs holding unbounded collections that are iterated in a single instruction
- Critical operations (liquidate, settle, distribute) gated behind whole-collection iteration
- No pagination/cursor for processing large datasets

## References
- Solana docs — compute budget and limits (https://solana.com/docs/core/fees#compute-budget)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — denial-of-service via compute exhaustion (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; unbounded-iteration DoS is a recognized medium audit finding for registries, reward distributors, and cranks.
