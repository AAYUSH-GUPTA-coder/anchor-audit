# Rule 050: Stack / CPI Depth Exhaustion

**Severity:** Low
**Category:** Runtime

## Description
The Solana runtime caps cross-program invocation depth (CPI calls can nest only a limited number of levels) and each program has a bounded stack frame size (large stack-allocated structures/arrays can blow the frame). Designs that chain many CPIs, or that place large data on the stack (especially recursively or in deep call chains), can hit these limits and fail at runtime — bricking instructions that depend on the full chain.

## Vulnerable pattern
```rust
// Deeply nested CPI chain: A -> B -> C -> D ... approaching the CPI depth
// limit. If the chain needs one more hop than allowed, the whole flow fails.
pub fn route(ctx: Context<Route>) -> Result<()> {
    invoke(&next_program_ix, accounts)?; // which itself CPIs further down
    Ok(())
}

// Large stack allocation inside a call that's already deep in a CPI chain:
let buffer = [0u8; 16_384]; // big stack frame, risks stack overflow
```

## Why this is dangerous
If an operation's success depends on a CPI chain near the depth limit, any addition (a new integration, a wrapper) tips it over and the instruction reverts — an availability failure that can freeze dependent funds. Oversized stack frames in deep chains can abort the program. Attackers may also craft inputs that force the deepest path.

## Fix pattern
```rust
// Keep CPI chains shallow; flatten orchestration into the top-level program
// rather than relaying through intermediate programs where avoidable.
// Move large data off the stack onto the heap or into accounts:
let buffer = vec![0u8; 16_384]; // heap-allocated; small stack frame

// Process multi-step flows as separate top-level instructions instead of
// one deep nested chain.
```

## Detection heuristic
- CPI chains that relay through several intermediate programs (each adding a level)
- Large fixed-size arrays/structs allocated on the stack (`[u8; N]`, big local structs), especially in deep call paths or recursion
- Recursive program logic without a strict depth bound
- Designs assuming an arbitrary number of nested CPIs will succeed

## References
- Solana docs — CPI depth and stack limits (https://solana.com/docs/core/cpi)
- Solana docs — program runtime limits (https://docs.solanalabs.com/runtime/programming-model/runtime)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; depth/stack limits surface as availability/robustness findings in audits of programs with deep integration chains.
