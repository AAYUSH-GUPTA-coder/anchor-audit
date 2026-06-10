# Rule 019: Missing Program ID Check on SPL CPIs

**Severity:** High
**Category:** CPI

## Description
A specialization of arbitrary CPI (Rule 017) for SPL Token / Token-2022 / Associated Token Program calls. Code constructs a token CPI but passes the token program as an unvalidated `AccountInfo`, or fails to distinguish SPL Token from Token-2022. The attacker substitutes a counterfeit token program that satisfies the call signature without moving real tokens.

## Vulnerable pattern
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let cpi_accounts = Transfer {
        from: ctx.accounts.user_token.to_account_info(),
        to: ctx.accounts.vault_token.to_account_info(),
        authority: ctx.accounts.user.to_account_info(),
    };
    // token_program is AccountInfo, never checked against spl_token::ID
    let cpi = CpiContext::new(ctx.accounts.token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi, amount)?;
    // program credits the user as if `amount` arrived
    Ok(())
}
```

## Why this is dangerous
With a fake token program, the "transfer" succeeds (the fake program returns Ok and does nothing), but the program's own bookkeeping credits the user a deposit. The attacker mints protocol credit for free, then withdraws real tokens through a legitimate path. Token-2022 confusion is a related risk: assuming SPL Token semantics for a Token-2022 mint with transfer hooks/fees.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    pub token_program: Program<'info, Token>, // pins spl_token::ID
    // ...
}
// For Token-2022 support, use anchor_spl::token_interface and the
// TokenInterface program type, and validate the mint's program owner.
```

## Detection heuristic
- Token CPIs (`token::transfer`, `mint_to`, `burn`, `set_authority`) built from a `token_program: AccountInfo` instead of `Program<'info, Token>` / `Interface`
- Token-account types as `AccountInfo` rather than `Account<'info, TokenAccount>` / `InterfaceAccount`
- No `require_keys_eq!(token_program.key(), spl_token::ID)` when raw `AccountInfo` is used
- Code that assumes received amount equals requested amount (ignores Token-2022 transfer fees)

## References
- Coral sealevel-attacks — 5-arbitrary-cpi (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/5-arbitrary-cpi)
- anchor_spl docs — Token / TokenInterface (https://docs.rs/anchor-spl/latest/anchor_spl/)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No single attributed public exploit; spoofed-token-program findings are common in public audits of staking and vault programs.
