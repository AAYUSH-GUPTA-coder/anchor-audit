# Rule 014: Predictable / Attacker-Controlled PDA Seeds

**Severity:** High
**Category:** PDA

## Description
A PDA's authority or identity derives entirely from seeds the attacker can choose, with no signer or ownership tying the PDA to a legitimate principal. Because anyone can compute and request initialization of such a PDA, the attacker front-runs or pre-creates the account, taking control of state the program treats as authoritative.

## Vulnerable pattern
```rust
#[derive(Accounts)]
#[instruction(market_id: u64)]
pub struct CreateMarket<'info> {
    #[account(
        init, payer = anyone, space = 8 + Market::INIT_SPACE,
        seeds = [b"market", market_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub market: Account<'info, Market>,
    #[account(mut)]
    pub anyone: Signer<'info>, // no admin/authority gate
}
```

## Why this is dangerous
Since `market_id` is attacker-chosen and no privileged signer is required, an attacker creates markets at addresses the protocol (or integrators) will later trust, seeding them with malicious parameters (fee recipient = attacker, oracle = attacker). Any later instruction that resolves "the market for id X" lands on the attacker's account.

## Fix pattern
```rust
#[derive(Accounts)]
#[instruction(market_id: u64)]
pub struct CreateMarket<'info> {
    #[account(
        init, payer = admin, space = 8 + Market::INIT_SPACE,
        seeds = [b"market", market_id.to_le_bytes().as_ref()],
        bump,
    )]
    pub market: Account<'info, Market>,
    #[account(mut, address = config.admin)] // only the protocol admin may create
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
}
```

## Detection heuristic
- `init` on a PDA whose seeds are fully attacker-supplied (instruction args, user-chosen ids) with no privileged `Signer` / `address =` gate
- PDAs whose seeds omit any principal binding (no `user.key()`, no `authority.key()`) for accounts that represent ownership
- Programs that resolve trusted singletons by attacker-chosen id without verifying who created them

## References
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Sec3 — Solana security best practices (https://www.sec3.dev/blog)
- Solana docs — program derived addresses (https://solana.com/docs/core/pda)

## Real-world exploits (if any)
No single attributed public exploit; front-running of permissionlessly-creatable PDAs is a recurring audit finding for market/pool factories.
