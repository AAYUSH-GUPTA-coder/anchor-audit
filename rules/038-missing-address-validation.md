# Rule 038: Missing `address` Validation on Fixed-Identity Accounts

**Severity:** Medium
**Category:** Constraints

## Description
Some accounts have a single correct value known at compile time or stored in config: a specific fee recipient, a known oracle, the protocol treasury, a particular program. When such an account is accepted without an `address = ...` constraint (or equivalent check), an attacker substitutes their own account, redirecting fees, feeding a fake oracle, or pointing the program at the wrong fixed dependency.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    // Fee should always go to the protocol treasury, but any account passes
    #[account(mut)]
    pub fee_recipient: Account<'info, TokenAccount>,
    // Oracle should be a specific known account, but unvalidated
    /// CHECK: price oracle
    pub oracle: AccountInfo<'info>,
    // ...
}
```

## Why this is dangerous
The attacker passes their own token account as `fee_recipient` and collects the protocol's fees, or supplies a fake `oracle` account with attacker-chosen prices that the program reads as authoritative (mispricing swaps/liquidations). Any account whose identity is supposed to be fixed but isn't pinned is an injection point.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Swap<'info> {
    #[account(mut, address = config.treasury)]
    pub fee_recipient: Account<'info, TokenAccount>,
    /// CHECK: pinned to the configured oracle
    #[account(address = config.oracle)]
    pub oracle: AccountInfo<'info>,
    pub config: Account<'info, Config>,
    // ...
}
```
For compile-time constants use `address = some_known_pubkey::ID`.

## Detection heuristic
- Accounts representing fixed dependencies (treasury, fee recipient, oracle, known program/account) without an `address =` constraint
- Pubkeys stored in config but the corresponding account passed unconstrained
- `/// CHECK:` accounts that are dereferenced for trusted data with no address pin
- Fee/royalty destinations taken from instruction input rather than config

## References
- Anchor docs — address constraint (https://www.anchor-lang.com/docs/account-constraints)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public exploit; unvalidated oracle/fee accounts are recurring medium/high audit findings, and fake-oracle injection underlies several DeFi price-manipulation incidents.
