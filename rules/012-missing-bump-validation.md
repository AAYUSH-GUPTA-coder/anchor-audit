# Rule 012: Missing Bump Validation

**Severity:** Medium
**Category:** PDA

## Description
A PDA account is accepted without any verification that its address actually derives from the expected seeds and bump for this program. If the account is typed `AccountInfo`/`UncheckedAccount` (or the handler recomputes nothing), an attacker can pass an arbitrary account where a PDA is expected, or pass a PDA derived from different seeds than intended.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: vault PDA — but nothing verifies the derivation
    #[account(mut)]
    pub vault_authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub user: Signer<'info>,
}
```

## Why this is dangerous
The program assumes `vault_authority` is *its* PDA for *this* vault, but any account passes. Depending on what the handler does, the attacker redirects authority checks, signs CPIs with the wrong derivation, or points shared logic at an account from an unrelated context. PDA identity is only meaningful if it is recomputed and compared.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    /// CHECK: derivation enforced by seeds + bump below
    #[account(
        mut,
        seeds = [b"vault_authority", vault_token.key().as_ref()],
        bump = vault.authority_bump, // stored canonical bump
    )]
    pub vault_authority: AccountInfo<'info>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(has_one = vault_token)]
    pub vault: Account<'info, Vault>,
    pub user: Signer<'info>,
}
```

## Detection heuristic
- Accounts whose names imply PDA roles (`*_authority`, `*_pda`, `escrow`, `vault`) with no `seeds`/`bump` constraint and no manual `find_program_address` comparison
- Handlers that use an account as a CPI signer (`invoke_signed`) whose address was never validated against those signer seeds
- `bump` arguments accepted from instruction data and used without verification (see Rule 013)

## References
- Coral sealevel-attacks — 7-bump-seed-canonicalization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-bump-seed-canonicalization)
- Anchor docs — account constraints, seeds/bump (https://www.anchor-lang.com/docs/account-constraints)
- Solana program security course — bump seed canonicalization (https://solana.com/developers/courses/program-security/bump-seed-canonicalization)

## Real-world exploits (if any)
No single attributed public exploit; unvalidated PDA inputs are a recurring high-severity finding in public OtterSec and Sec3 reports.
