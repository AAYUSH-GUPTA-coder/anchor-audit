# Rule 046: Associated Token Account Assumption Errors

**Severity:** Medium
**Category:** SPL Token

## Description
Code assumes a token account is *the* canonical associated token account (ATA) for a given wallet+mint — correctly derived, already existing, and the only one — without enforcing it. A wallet can hold many token accounts for the same mint, and only the ATA is at the deterministic derived address. Trusting an unconstrained "ATA" lets an attacker pass a non-canonical token account, and assuming existence causes failures or, worse, silent misrouting.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Payout<'info> {
    /// CHECK: assumed to be the recipient's ATA, but not derived/verified
    #[account(mut)]
    pub recipient_ata: AccountInfo<'info>,
    pub recipient: SystemAccount<'info>,
    pub mint: Account<'info, Mint>,
    // ...
}
```

## Why this is dangerous
The attacker passes a token account they control (for the right mint but at a non-ATA address, or owned by a different wallet) as `recipient_ata`, redirecting a payout. Conversely, assuming the ATA already exists makes the instruction fail when it doesn't, bricking the flow — or pushes developers to create it without checking who pays. ATA identity must be derived and checked, not assumed.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Payout<'info> {
    #[account(
        mut,
        associated_token::mint = mint,
        associated_token::authority = recipient, // enforces canonical ATA
    )]
    pub recipient_ata: Account<'info, TokenAccount>,
    pub recipient: SystemAccount<'info>,
    pub mint: Account<'info, Mint>,
    // For creation: use `init` with associated_token::* + the ATA program.
}
```

## Detection heuristic
- Accounts named `*_ata` typed as `AccountInfo` or `TokenAccount` without `associated_token::*` constraints
- Token destinations assumed canonical without `associated_token::mint`/`authority` (or a `get_associated_token_address` comparison)
- Code that assumes an ATA exists with no `init`/`init_if_needed` or existence handling
- ATA derivation done off-chain and trusted on-chain without re-derivation

## References
- anchor_spl docs — associated_token constraints (https://docs.rs/anchor-spl/latest/anchor_spl/associated_token/)
- SPL Associated Token Account program docs (https://spl.solana.com/associated-token-account)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; ATA assumption errors are common medium audit findings, especially payout redirection via non-canonical token accounts.
