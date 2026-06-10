# Rule 034: Missing `has_one` Relationship Enforcement

**Severity:** High
**Category:** Auth

## Description
A state account stores pubkeys describing its relationships (`owner`, `mint`, `vault`, `authority`), but the instruction doesn't enforce that the corresponding passed-in accounts actually match those stored fields. `has_one = x` makes Anchor assert `account.x == x.key()`. Omitting it (and not replacing it with an explicit check) lets an attacker pass a mismatched but otherwise-valid account.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Harvest<'info> {
    #[account(mut)] // Farm stores `authority` and `reward_vault` — neither enforced
    pub farm: Account<'info, Farm>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
}

pub fn harvest(ctx: Context<Harvest>) -> Result<()> {
    // Uses farm.reward_vault implicitly, but reward_vault could be any account
    // and authority could be anyone — no link to farm.authority is checked.
    Ok(())
}
```

## Why this is dangerous
Without `has_one`, the signer need not be the farm's authority, and the reward vault need not be the farm's real vault. The attacker harvests someone else's farm, or redirects rewards to a vault they control, because the program trusts the passed accounts instead of the relationships recorded in state.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Harvest<'info> {
    #[account(mut, has_one = authority, has_one = reward_vault)]
    pub farm: Account<'info, Farm>,
    pub authority: Signer<'info>,
    #[account(mut)]
    pub reward_vault: Account<'info, TokenAccount>,
}
```
Each `has_one = field` requires a matching context account named `field` and asserts equality.

## Detection heuristic
- State structs with relationship pubkey fields (`authority`, `owner`, `mint`, `vault`, `pool`) whose instructions lack matching `has_one`
- Accounts used in logic by reference to a stored pubkey but passed in unconstrained
- Authority signers not tied to the state account via `has_one`/`address`/explicit check
- `require_keys_eq!` checks that are present in some handlers but missing in siblings

## References
- Anchor docs — has_one constraint (https://www.anchor-lang.com/docs/account-constraints)
- Solana program security course — account data matching (https://solana.com/developers/courses/program-security/account-data-matching)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public headline exploit; missing relationship checks are among the most common high/critical audit findings (closely related to Cashio's unvalidated account chain).
