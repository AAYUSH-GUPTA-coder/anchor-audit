# Rule 049: Log Spam / Excessive Logging DoS

**Severity:** Low
**Category:** Runtime

## Description
`msg!` and other logging consume compute units and contribute to transaction log size, which is itself bounded. Logging attacker-controlled or unbounded data (a user-supplied string, every element of a collection, large buffers) lets an attacker inflate compute/log usage to make an instruction fail, or simply wastes the budget so legitimately-needed work no longer fits. Logging inside hot loops compounds the cost.

## Vulnerable pattern
```rust
pub fn record(ctx: Context<Record>, memo: String) -> Result<()> {
    // Attacker-controlled, unbounded string logged verbatim; large memos
    // burn compute and bloat logs, and can push the tx over its limits.
    msg!("memo: {}", memo);
    for item in ctx.accounts.list.items.iter() {
        msg!("item: {:?}", item); // logging in a loop multiplies the cost
    }
    Ok(())
}
```

## Why this is dangerous
Excessive logging can exhaust the compute budget (causing the instruction to fail) and inflate transaction logs, degrading RPC/indexer performance for everyone reading the program's output. When a required instruction logs unbounded input, an attacker can deny its use; even absent an attacker, it raises costs and can intermittently break the path.

## Fix pattern
```rust
pub fn record(ctx: Context<Record>, memo: String) -> Result<()> {
    require!(memo.len() <= MAX_MEMO_LEN, ErrorCode::MemoTooLong);
    // Avoid logging raw user data; log bounded, structured summaries only.
    msg!("record: memo_len={}", memo.len());
    // Do not log inside large loops; emit a single summary if needed.
    Ok(())
}
```
Prefer structured Anchor events (`emit!`) over verbose `msg!`, and never log full attacker-controlled buffers.

## Detection heuristic
- `msg!` formatting attacker-controlled strings/buffers without a length cap
- Logging inside loops over collections or `remaining_accounts`
- Verbose debug logging (`{:?}` on large structs) left in production paths
- No bound on user-supplied fields that are subsequently logged

## References
- Solana docs — program logging and limits (https://solana.com/docs/programs/debugging#logging)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — compute and log DoS (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; log/compute spam is a low-severity hygiene and availability finding in audits.
