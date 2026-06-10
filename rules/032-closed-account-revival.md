# Rule 032: Closed Account Revival

**Severity:** High
**Category:** Auth

## Description
The counterpart to Rule 010. An account "closed" by only draining its lamports keeps its data for the rest of the transaction and is garbage-collected only after the transaction ends. An attacker re-funds the account (sending it rent-exempt lamports in a later instruction of the same transaction, or before GC) so it survives, then reuses the stale-but-valid account in subsequent instructions that assume it was destroyed.

## Vulnerable pattern
```rust
pub fn close(ctx: Context<Close>) -> Result<()> {
    let acc = ctx.accounts.position.to_account_info();
    let dest = ctx.accounts.owner.to_account_info();
    **dest.try_borrow_mut_lamports()? += acc.lamports();
    **acc.try_borrow_mut_lamports()? = 0; // data NOT zeroed, no closed marker
    Ok(())
}
// Attacker, in the same tx: transfer rent-exempt lamports back to `position`,
// then call an instruction that still treats `position` as a live, funded position.
```

## Why this is dangerous
The revived account retains its old discriminator and field values, so type and owner checks still pass. The attacker double-claims rewards tied to a "closed" position, keeps using collateral that was supposed to be released, or replays one-time actions. The lamport drain alone is not a close.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Close<'info> {
    #[account(mut, has_one = owner, close = owner)] // zeroes data + closed marker
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
}
```
Anchor's `close` writes `CLOSED_ACCOUNT_DISCRIMINATOR`, so a revived account fails the discriminator check on next use.

## Detection heuristic
- Manual lamport-draining closes (see Rule 010) without zeroing data and writing a closed discriminator
- Accounts that are "closed" in one instruction and read in another within plausible transaction flows
- Reward/claim/one-time-action accounts closed without Anchor's `close` constraint
- No re-check of discriminator/initialized flag on accounts that may have been closed

## References
- Coral sealevel-attacks — 9-closing-accounts (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-closing-accounts)
- Solana program security course — closing accounts & revival (https://solana.com/developers/courses/program-security/closing-accounts)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)

## Real-world exploits (if any)
No single attributed public headline exploit; account-revival is a well-documented critical pattern in the sealevel-attacks corpus and recurs in audits.
