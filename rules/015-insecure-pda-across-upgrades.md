# Rule 015: Insecure PDA Layout Across Upgrades

**Severity:** Medium
**Category:** PDA

## Description
Solana programs are upgradeable, but PDA accounts created by an old version persist with their old data layout. If an upgrade changes an account struct's fields, order, or size — or changes the seed scheme — without a versioning/migration strategy, the new code misinterprets existing accounts' bytes or can no longer derive their addresses.

## Vulnerable pattern
```rust
// v1
#[account]
pub struct Vault { pub authority: Pubkey, pub balance: u64 }

// v2 inserts a field in the middle — existing accounts now misparse:
#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub admin: Pubkey, // NEW, shifts `balance` bytes
    pub balance: u64,
}
// No version tag, no migration instruction.
```

## Why this is dangerous
Old accounts deserialize with shifted fields: `balance` reads bytes that used to be part of another field, producing wrong values that flow into withdrawal/accounting logic. If the seed scheme changed instead, old accounts become unreachable, stranding user funds. Either way an attacker can exploit the mismatch or the protocol simply loses correctness.

## Fix pattern
```rust
#[account]
pub struct Vault {
    pub version: u8, // bump on layout change
    pub authority: Pubkey,
    pub balance: u64,
    pub admin: Pubkey, // append new fields at the END
}
// Provide an explicit `migrate_vault` instruction that reads version,
// reallocs if needed, and writes the new layout. Append-only fields +
// realloc with zero-init (see Rule 040) preserve old data.
```

## Detection heuristic
- `#[account]` structs without a `version`/`schema` field in an upgradeable program
- Field insertions/removals/reorderings in account structs between versions (check git history)
- Seed-scheme changes for already-initialized PDAs with no migration instruction
- `realloc` on existing accounts without preserving prior field offsets

## References
- Anchor docs — program upgrades and account layout (https://www.anchor-lang.com/docs)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — Solana program upgrade considerations (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; layout-migration bugs surface in audits of long-lived upgradeable protocols and can corrupt accounting silently.
