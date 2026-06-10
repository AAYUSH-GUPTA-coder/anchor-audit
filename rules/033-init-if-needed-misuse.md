# Rule 033: `init_if_needed` Misuse

**Severity:** High
**Category:** Auth

## Description
Anchor's `init_if_needed` initializes an account if it doesn't exist and otherwise loads it. It is convenient but dangerous: when the account already exists, the initialization body is skipped, so any field-setting logic placed in the handler runs against existing state — or, conversely, an attacker can pre-create the account so "needed" init never happens. Used without a follow-up guard, it enables reinitialization-style takeovers and state resets.

## Vulnerable pattern
```rust
#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + Position::INIT_SPACE,
        seeds = [b"position", user.key().as_ref()],
        bump,
    )]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    // Runs every call. On an existing account this is fine; but if the
    // handler (re)sets owner/authority here, it overwrites it each call.
    ctx.accounts.position.owner = ctx.accounts.user.key();
    ctx.accounts.position.amount += amount;
    Ok(())
}
```

## Why this is dangerous
If sensitive fields are (re)assigned in the handler, a second caller's data can clobber the first's (when seeds aren't user-bound), or accumulated state is reset. When `init_if_needed` is enabled program-wide, every account it touches must be analyzed for reinitialization (Rule 031). Attackers also pre-create accounts to control which branch runs.

## Fix pattern
```rust
pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
    let position = &mut ctx.accounts.position;
    // Only set identity once; never overwrite on subsequent calls.
    if position.owner == Pubkey::default() {
        position.owner = ctx.accounts.user.key();
    } else {
        require_keys_eq!(position.owner, ctx.accounts.user.key());
    }
    position.amount = position.amount.checked_add(amount).ok_or(ErrorCode::Overflow)?;
    Ok(())
}
```
Prefer a separate explicit `init` instruction where feasible; bind PDA seeds to the user.

## Detection heuristic
- `init_if_needed` anywhere — each use needs reinitialization analysis
- Handlers that unconditionally assign identity/authority fields on an `init_if_needed` account
- `init_if_needed` PDAs whose seeds are not bound to the calling principal
- The `init-if-needed` Anchor feature enabled without per-account guards

## References
- Anchor docs — init_if_needed (https://www.anchor-lang.com/docs/account-constraints)
- Solana program security course — reinitialization attacks (https://solana.com/developers/courses/program-security/reinitialization-attacks)
- Sec3 — init_if_needed risks (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; `init_if_needed` misuse is a recurring high-severity audit finding and the reason the feature is gated behind a Cargo flag.
