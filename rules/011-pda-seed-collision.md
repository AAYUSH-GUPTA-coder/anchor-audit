# Rule 011: PDA Seed Collision

**Severity:** High
**Category:** PDA

## Description
Two logically distinct PDAs can derive to the same address when their seed schemes overlap. Seeds are concatenated raw bytes with no delimiters or type tags, so `["vault", user, mint]` and `["vault", mint, user]`-style ambiguities, variable-length seeds (user-supplied strings), or two account kinds sharing a prefix can all collide. A PDA created for one purpose then satisfies derivation checks for another.

## Vulnerable pattern
```rust
// Two account kinds, same seed shape — both derive from ["pool", key]
#[account(seeds = [b"pool", base_mint.key().as_ref()], bump)]
pub lending_pool: Account<'info, LendingPool>,

// elsewhere in the program:
#[account(seeds = [b"pool", quote_mint.key().as_ref()], bump)]
pub staking_pool: Account<'info, StakingPool>,

// Or: variable-length user input lets ["ab" + "cd"] == ["a" + "bcd"]
#[account(seeds = [name.as_bytes(), suffix.as_bytes()], bump)]
pub named_account: Account<'info, Named>,
```

## Why this is dangerous
An attacker crafts inputs so the address of an account they control (or one with favorable state) derives identically to the account the program expects in a different context. Seed checks pass, and the program operates on the wrong account — mixing pools, reusing one account for two roles, or hijacking a namespace.

## Fix pattern
```rust
// Distinct literal prefixes per account kind, fixed-length seeds,
// and a length cap on any user-supplied seed component
#[account(seeds = [b"lending_pool", base_mint.key().as_ref()], bump)]
pub lending_pool: Account<'info, LendingPool>,

#[account(seeds = [b"staking_pool", quote_mint.key().as_ref()], bump)]
pub staking_pool: Account<'info, StakingPool>,
```

## Detection heuristic
- Multiple account types whose `seeds = [...]` share the same literal prefix and shape
- Seeds containing user-controlled variable-length data (strings, vecs) — adjacent variable-length seeds are always ambiguous
- The same seed tuple used by more than one instruction for different account types

## References
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Sec3 — How to audit Solana smart contracts (https://www.sec3.dev/blog)
- Solana docs — program derived addresses (https://solana.com/docs/core/pda)

## Real-world exploits (if any)
No public headline exploit; seed-design findings appear in public Neodyme and Sec3 audit reports, usually rated high due to namespace hijack potential.
