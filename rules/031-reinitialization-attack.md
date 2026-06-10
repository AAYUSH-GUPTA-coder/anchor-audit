# Rule 031: Reinitialization Attack

**Severity:** High
**Category:** Auth

## Description
An initialization instruction can be invoked more than once against the same account, resetting its state. If the account is already in use — holding a balance, an authority, or accumulated state — a second `init`-style call lets an attacker overwrite critical fields (e.g. reset the authority to themselves) or wipe accounting. Manual init flows that don't guard against re-entry, and `init_if_needed` used carelessly, are the usual culprits.

## Vulnerable pattern
```rust
pub fn initialize(ctx: Context<Initialize>, authority: Pubkey) -> Result<()> {
    let state = &mut ctx.accounts.state;
    // No check whether `state` was already initialized — callable repeatedly
    state.authority = authority;
    state.balance = 0; // wipes any existing balance on re-call
    Ok(())
}
```

## Why this is dangerous
After legitimate setup, the attacker calls `initialize` again, setting `authority` to their own key (taking over the account) or zeroing accounting fields to erase debts/balances. Because the account already exists and is owned by the program, only an explicit "already initialized" guard prevents the overwrite.

## Fix pattern
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    // `init` fails if the account already exists / has a discriminator
    #[account(init, payer = payer, space = 8 + State::INIT_SPACE)]
    pub state: Account<'info, State>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}
// For manual flows: require!(!state.is_initialized, ErrorCode::AlreadyInit);
//                   state.is_initialized = true;
```

## Detection heuristic
- "initialize"/"setup"/"create" handlers that write state without `init` or an `is_initialized` guard
- `init_if_needed` on accounts whose re-initialization would reset sensitive fields (see Rule 033)
- Authority/owner fields assignable by an instruction reachable more than once
- Manual account creation followed by configuration that can be replayed

## References
- Coral sealevel-attacks — 4-initialization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/4-initialization)
- Solana program security course — reinitialization attacks (https://solana.com/developers/courses/program-security/reinitialization-attacks)
- Anchor docs — init / init_if_needed (https://www.anchor-lang.com/docs/account-constraints)

## Real-world exploits (if any)
No single attributed public headline exploit; reinitialization is a standard high/critical finding in public audits, especially for config and authority accounts.
