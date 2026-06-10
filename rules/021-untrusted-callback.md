# Rule 021: Untrusted Callback Execution

**Severity:** High
**Category:** CPI

## Description
A program invokes a caller-supplied program as a "callback" or "hook" — flash-loan receivers, transfer hooks, router callbacks — without constraining which program may be called or validating the state it leaves behind. The callback runs arbitrary attacker code, often while the calling program is mid-operation and holding elevated authority or unsettled balances.

## Vulnerable pattern
```rust
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    let pre = ctx.accounts.vault.amount;
    token::transfer(/* vault -> borrower */, amount)?;
    // Calls an arbitrary borrower-supplied program with no allowlist...
    invoke(&ctx.accounts.callback_ix, ctx.remaining_accounts)?;
    // ...and never re-checks that the loan was repaid.
    Ok(())
}
```

## Why this is dangerous
The borrower's callback program does whatever it wants with the borrowed funds and the accounts handed to it, then returns. Without a post-callback invariant check (balance restored + fee), the attacker keeps the loan. More broadly, any unvalidated callback can re-enter sibling instructions, manipulate oracle/price accounts, or abuse the caller's signer authority.

## Fix pattern
```rust
pub fn flash_loan(ctx: Context<FlashLoan>, amount: u64) -> Result<()> {
    let pre = ctx.accounts.vault.amount;
    let fee = amount / 1000;
    token::transfer(/* vault -> borrower */, amount)?;
    invoke(&ctx.accounts.callback_ix, ctx.remaining_accounts)?;
    ctx.accounts.vault.reload()?;
    require!(ctx.accounts.vault.amount >= pre + fee, ErrorCode::LoanNotRepaid);
    Ok(())
}
```
Where possible, allowlist callback program IDs and minimize the accounts/authority exposed to them.

## Detection heuristic
- `invoke`/`invoke_signed` of a program ID taken from instruction data or `remaining_accounts` with no allowlist
- Flash-loan / hook patterns lacking a post-callback `reload()` + invariant assertion
- Callbacks passed the calling program's PDA signer or mutable core accounts

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — flash loan and callback safety (https://www.sec3.dev/blog)
- SPL Token-2022 — transfer hook interface (https://spl.solana.com/token-2022/extensions#transfer-hook)

## Real-world exploits (if any)
Flash-loan callbacks that fail to enforce repayment invariants have driven multiple DeFi drains across chains; on Solana this is a standard high-severity audit finding for lending/flash-loan programs.
