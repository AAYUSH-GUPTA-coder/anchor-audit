# Rule 005: Sysvar Spoofing

**Severity:** High
**Category:** Account validation

## Description
Sysvar accounts (Clock, Rent, Instructions, EpochSchedule, …) live at well-known addresses, but a program that accepts "the clock account" or "the instructions sysvar" as an untyped `AccountInfo` and parses its data manually never verifies the address. An attacker passes a fake account with attacker-crafted "sysvar" contents — fake timestamps, fake serialized instructions — and the program trusts it.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Verify<'info> {
    /// CHECK: instructions sysvar
    pub instructions: AccountInfo<'info>,
}

pub fn verify(ctx: Context<Verify>) -> Result<()> {
    // Deprecated non-checked API: reads whatever account was passed
    let ix = solana_program::sysvar::instructions::load_instruction_at(
        0,
        &ctx.accounts.instructions.data.borrow(),
    )?;
    // ... trusts `ix` to be a real instruction in this transaction
    Ok(())
}
```

## Why this is dangerous
Whatever the program reads from the spoofed account — a timestamp gating a withdrawal, a "previous instruction" proving a signature verification ran — is attacker-controlled. In the worst case the attacker fabricates proof that a security check happened when it never did, bypassing the program's core authorization.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Verify<'info> {
    /// CHECK: address constraint pins this to the real sysvar
    #[account(address = solana_program::sysvar::instructions::ID)]
    pub instructions: AccountInfo<'info>,
}

// In the handler, prefer the checked API:
let ix = solana_program::sysvar::instructions::load_instruction_at_checked(
    0, &ctx.accounts.instructions)?;
```
For Clock/Rent, use `Sysvar<'info, Clock>` / `Clock::get()?` instead of passing accounts at all.

## Detection heuristic
- Sysvar-named accounts (`clock`, `rent`, `instructions`, `recent_blockhashes`) typed as `AccountInfo` without an `address =` constraint
- Use of deprecated `load_instruction_at` / `load_current_index` (non-`_checked` variants)
- Manual parsing of sysvar account data instead of `Clock::get()` / `Rent::get()`

## References
- Neodyme — Solana common pitfalls: solana_program::sysvar confusion (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Solana docs — sysvar cluster data (https://docs.solanalabs.com/runtime/sysvars)

## Real-world exploits (if any)
Wormhole bridge (February 2022, ~$325M): the guardian-signature verification used the deprecated non-checked instructions-sysvar API, letting the attacker substitute a fake sysvar account and forge a "signatures verified" result to mint 120k wETH.
