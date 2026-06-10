# Rule 041: `init` Without `payer` (or Wrong Payer)

**Severity:** Low
**Category:** Constraints

## Description
The `init` constraint requires a `payer` to fund the new account's rent-exemption. Beyond the compile/runtime requirement, the *choice* of payer matters: using a program-controlled or shared account as payer, or letting a payer fund accounts without their explicit signature, can drain the wrong party. The related defect is initializing accounts at someone else's expense or griefing a shared funding source.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct CreateEntry<'info> {
    #[account(
        init,
        space = 8 + Entry::INIT_SPACE,
        payer = treasury, // shared protocol account pays for anyone's account
    )]
    pub entry: Account<'info, Entry>,
    #[account(mut)]
    pub treasury: Account<'info, TokenAccount>, // not the caller
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## Why this is dangerous
If a shared/treasury account funds arbitrary user-created accounts, an attacker creates many accounts to drain the treasury's lamports (griefing / denial of funds). Conversely, a missing/incorrect payer makes legitimate initialization fail. The payer should normally be the caller who benefits, and must sign.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct CreateEntry<'info> {
    #[account(
        init,
        space = 8 + Entry::INIT_SPACE,
        payer = user, // the caller funds their own account
        seeds = [b"entry", user.key().as_ref()],
        bump,
    )]
    pub entry: Account<'info, Entry>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}
```

## Detection heuristic
- `init` with `payer = <shared/treasury/PDA>` rather than the calling principal
- `init` where the payer is not a `Signer` (mut) in the same context
- Permissionless instructions that initialize accounts funded by a protocol-owned account
- Account creation with no per-caller rate limiting funded from a common source

## References
- Anchor docs — init and payer (https://www.anchor-lang.com/docs/account-constraints)
- The Anchor Book — init constraint (https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html)
- Solana docs — rent and account creation (https://solana.com/docs/core/fees#rent)

## Real-world exploits (if any)
No single attributed public exploit; treasury-funded-init griefing and payer misconfiguration are low/medium audit and robustness findings.
