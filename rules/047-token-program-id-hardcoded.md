# Rule 047: Token Program ID Hardcoded vs. Validated

**Severity:** Medium
**Category:** SPL Token

## Description
With SPL Token and Token-2022 both in use, a program must be deliberate about which token program it targets. Two failure modes: (1) hardcoding `spl_token::ID` while accepting mints/accounts that actually belong to Token-2022 (or vice-versa), causing CPI failures or wrong assumptions; and (2) accepting the token program as an unvalidated account so the wrong (or fake) program is used. The program ID must match the program that actually owns the token accounts involved.

## Vulnerable pattern
```rust
pub fn transfer_out(ctx: Context<TransferOut>, amount: u64) -> Result<()> {
    // Hardcodes legacy SPL Token, but the mint is a Token-2022 mint, so the
    // accounts are owned by the Token-2022 program — this CPI targets the
    // wrong program ID for these accounts.
    let cpi = CpiContext::new(
        ctx.accounts.token_program.to_account_info(), // assumed spl_token::ID
        Transfer { /* ... */ },
    );
    token::transfer(cpi, amount)?;
    Ok(())
}
```

## Why this is dangerous
Mismatching the token program against the token accounts' actual owner program makes transfers fail (availability) or, when combined with unvalidated program accounts, lets a fake token program be injected (Rule 019). Hardcoding one variant silently breaks compatibility for the other and can be steered by an attacker choosing a Token-2022 mint where SPL Token is assumed.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct TransferOut<'info> {
    // Interface accepts either SPL Token or Token-2022, verified to match
    // the accounts' owning program.
    pub token_program: Interface<'info, TokenInterface>,
    #[account(mut)]
    pub from: InterfaceAccount<'info, TokenAccount>,
    #[account(mut)]
    pub to: InterfaceAccount<'info, TokenAccount>,
    pub authority: Signer<'info>,
}
// Use anchor_spl::token_interface CPIs so the call routes to the correct program.
```

## Detection heuristic
- Hardcoded `spl_token::ID` / `Program<'info, Token>` while the program intends to support Token-2022 (or vice-versa)
- Token accounts as `Account<TokenAccount>` (legacy) when mints may be Token-2022 — use `InterfaceAccount`
- Token program passed as `AccountInfo` without an ID check (overlaps Rule 019)
- No verification that `token_program.key()` equals the owner program of the passed token accounts

## References
- anchor_spl docs — token_interface / Interface (https://docs.rs/anchor-spl/latest/anchor_spl/token_interface/)
- SPL Token-2022 docs (https://spl.solana.com/token-2022)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; token-program mismatch and Token-2022 compatibility gaps are increasingly common medium audit findings.
