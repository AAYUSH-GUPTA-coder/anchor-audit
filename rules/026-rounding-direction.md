# Rule 026: Incorrect Rounding Direction

**Severity:** Medium
**Category:** Math

## Description
When integer math must round, the direction must always favor the protocol, not the user. Minting shares should round *down*; charging fees or computing how much a user must repay should round *up*. A consistent "round in the user's favor" or naive truncation lets an attacker repeatedly extract the rounding difference, and in share-based vaults enables inflation/donation attacks.

## Vulnerable pattern
```rust
// Withdrawal: assets owed for `shares`. Truncating division rounds DOWN
// the amount burned-for but the protocol pays out the rounded-up assets
// elsewhere — or, mint rounds UP giving free shares:
let shares_to_mint = (deposit * total_shares + total_assets) / total_assets; // rounds up on mint
```

## Why this is dangerous
If minting rounds up, an attacker deposits tiny amounts many times, each rounding up to extra shares, and redeems for more than deposited. The first-depositor / share-inflation attack combines zero-supply edge cases with favorable rounding to steal later depositors' funds. Rounding that favors the user is a slow, repeatable drain.

## Fix pattern
```rust
// Mint shares: round DOWN (truncating division is correct here)
let shares = deposit.checked_mul(total_shares)?.checked_div(total_assets)?;
// Repay / fee owed by user: round UP
let owed = amount.checked_mul(rate)?
    .checked_add(scale - 1)?       // ceil division
    .checked_div(scale)?;
```
Add a minimum-liquidity / dead-shares mechanism to neutralize first-depositor inflation.

## Detection heuristic
- Share-minting math that rounds up, or redemption math that rounds up in the user's favor
- Fee/interest/repayment calculations that truncate (round down) what the user owes
- Vaults with no first-depositor protection (dead shares, minimum liquidity)
- Mixed rounding directions used inconsistently between deposit and withdraw paths

## References
- Sec3 — rounding and share inflation (https://www.sec3.dev/blog)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- OpenZeppelin — ERC4626 inflation attack writeups (concept reference) (https://docs.openzeppelin.com/contracts/4.x/erc4626)

## Real-world exploits (if any)
Share-inflation/first-depositor attacks have caused losses in vault protocols across ecosystems; rounding-direction errors are a standard medium/high audit finding.
