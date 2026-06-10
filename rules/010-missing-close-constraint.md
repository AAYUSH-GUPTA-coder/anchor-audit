# Rule 010: Missing or Improper Close Constraint

**Severity:** Medium
**Category:** Account validation

## Description
Closing an account on Solana means draining its lamports, but a "manual close" that only transfers lamports leaves the account's data intact for the rest of the transaction — and garbage collection only happens after the transaction ends. A close path that doesn't zero the data and mark the account closed (or that doesn't exist at all, stranding rent) is incorrect. Anchor's `close = receiver` constraint performs all required steps.

## Vulnerable pattern
```rust
pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
    let position = ctx.accounts.position.to_account_info();
    let dest = ctx.accounts.receiver.to_account_info();
    // Lamports drained — but data and discriminator left intact
    **dest.try_borrow_mut_lamports()? += position.lamports();
    **position.try_borrow_mut_lamports()? = 0;
    Ok(())
}
```

## Why this is dangerous
Within the same transaction, the attacker sends rent-exempt lamports back to the "closed" account in a later instruction, preventing garbage collection. The account survives with stale data and can be passed into other instructions as if still live — e.g. a closed loan position that still vouches for collateral (see Rule 032 for the revival half of this attack).

## Fix pattern
```rust
#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut, has_one = owner, close = receiver)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub receiver: SystemAccount<'info>,
    pub owner: Signer<'info>,
}
```
Anchor's `close` drains lamports, zeroes data, and writes the `CLOSED_ACCOUNT_DISCRIMINATOR`.

## Detection heuristic
- Manual lamport-drain "closes" (`try_borrow_mut_lamports` to zero) without zeroing `data` and setting a closed discriminator
- Account types that are initialized somewhere but have no close path at all (stranded rent, unbounded account growth)
- Close instructions missing an authority check on who may close

## References
- Coral sealevel-attacks — 9-closing-accounts (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/9-closing-accounts)
- Solana program security course — closing accounts (https://solana.com/developers/courses/program-security/closing-accounts)
- Anchor docs — account constraints, close (https://www.anchor-lang.com/docs/account-constraints)

## Real-world exploits (if any)
No single attributed public exploit; the revival variant is a standard critical audit finding (see Rule 032).
