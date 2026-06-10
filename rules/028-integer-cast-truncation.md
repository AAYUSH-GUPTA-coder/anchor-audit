# Rule 028: Integer Cast Truncation

**Severity:** Medium
**Category:** Math

## Description
The Rust `as` operator performs a silent, lossy cast: `large_u128 as u64`, `u64 as u32`, or `i64 as u8` discard high bits without any error. Casting a computed value down to a narrower type — common when interfacing with `u64` token amounts after `u128` intermediate math — can wrap a large number to a small one, falsifying amounts and bypassing bound checks.

## Vulnerable pattern
```rust
let scaled: u128 = (amount as u128) * (price as u128) / DENOM;
// scaled may exceed u64::MAX; `as u64` silently keeps only the low 64 bits
let payout: u64 = scaled as u64;
token::transfer(/* ... */, payout)?;
```

## Why this is dangerous
A `u128` result that legitimately exceeds `u64::MAX` wraps to a small `payout`, or a near-boundary value wraps in a way the attacker can engineer to mint/withdraw an amount that passes earlier `<=` checks (performed in the wide type) but executes with a different narrow value. Downcasting indices or counts (`as u32`, `as u8`) can also wrap loop bounds.

## Fix pattern
```rust
let scaled: u128 = (amount as u128)
    .checked_mul(price as u128).ok_or(ErrorCode::Overflow)?
    .checked_div(DENOM).ok_or(ErrorCode::DivByZero)?;
// Fallible conversion: errors instead of truncating
let payout: u64 = u64::try_from(scaled).map_err(|_| ErrorCode::Overflow)?;
token::transfer(/* ... */, payout)?;
```

## Detection heuristic
- `as u64` / `as u32` / `as u16` / `as u8` applied to wider computed values (especially after `u128` math)
- Narrowing casts on token amounts, lamports, prices, or indices
- Casts used in place of `try_from` / `try_into` where the source range exceeds the target
- Signed/unsigned casts (`as i64` ↔ `as u64`) on values that could be negative or large

## References
- Neodyme — Solana common pitfalls: casting (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Rust reference — numeric cast semantics (https://doc.rust-lang.org/reference/expressions/operator-expr.html#numeric-cast)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; truncating casts are a recurring audit finding wherever `u128` intermediate math is narrowed back to `u64`.
