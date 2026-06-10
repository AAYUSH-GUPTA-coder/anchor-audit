# Rule 029: Off-by-One Errors

**Severity:** Low
**Category:** Math

## Description
Boundary mistakes in iteration, indexing, slicing, and threshold comparisons: `<` where `<=` was meant, loops that skip the last element or read one past the end, and slice ranges that drop or duplicate a byte. On Solana these surface in manual account-data parsing, `remaining_accounts` iteration, and threshold checks (quorums, caps, expiry).

## Vulnerable pattern
```rust
// Quorum check off by one: requires strictly more than half, but the
// intent was "at least half" — or vice-versa. Either way the boundary
// case is wrong.
require!(votes > total / 2, ErrorCode::QuorumNotMet);

// Slice that drops the last byte of the discriminator/region:
let body = &data[8..data.len() - 1];
```

## Why this is dangerous
A threshold off by one lets a proposal pass with one vote too few, or blocks a legitimate one. Slice/index off-by-ones either panic (DoS for that instruction) or, worse, read adjacent bytes, mis-parsing a field that feeds into authorization or amount logic. In `remaining_accounts` loops, an off-by-one can skip a required account check.

## Fix pattern
```rust
// State the boundary explicitly and test it:
require!(votes.checked_mul(2).ok_or(ErrorCode::Overflow)? >= total,
         ErrorCode::QuorumNotMet); // >= half

let body = data.get(8..).ok_or(ErrorCode::Malformed)?; // no manual len math
```
Prefer `.get(range)` (returns `Option`) over direct indexing, and add explicit boundary tests.

## Detection heuristic
- Threshold comparisons (`>`, `>=`, `<`, `<=`) on quorums, caps, expiries, min/max where the boundary intent is ambiguous
- Manual slice ranges with `+ 1` / `- 1` / `len() - 1` arithmetic
- `for i in 0..n` loops indexing `arr[i + 1]` or `arr[i - 1]`
- Direct slice indexing (`data[a..b]`) on attacker-sized data instead of `.get`

## References
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Sec3 — common Solana logic bugs (https://www.sec3.dev/blog)
- Rust docs — slice::get (https://doc.rust-lang.org/std/primitive.slice.html#method.get)

## Real-world exploits (if any)
No single attributed public exploit; off-by-one bugs are common low/medium audit findings, occasionally escalating when they govern authorization thresholds.
