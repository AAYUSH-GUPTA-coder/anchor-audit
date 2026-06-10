# Rule 013: Non-Canonical Bump Accepted

**Severity:** High
**Category:** PDA

## Description
For any set of seeds there are typically several valid bump values that produce off-curve addresses, but only one *canonical* bump (the highest, found by `find_program_address`). If a program accepts a caller-supplied bump and validates only that the resulting address is a valid PDA — rather than that it used the canonical bump — an attacker can derive multiple distinct, valid PDAs from the same logical seeds.

## Vulnerable pattern
```rust
#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct Init<'info> {
    #[account(
        init, payer = user, space = 8 + 32,
        seeds = [b"user", user.key().as_ref()],
        bump, // with the bump taken from instruction args, any valid bump passes
    )]
    pub user_pda: Account<'info, UserData>,
    #[account(mut)]
    pub user: Signer<'info>,
}
// handler trusts the `bump` arg and calls create_program_address with it
```

## Why this is dangerous
The attacker initializes several PDAs for the same seeds using different non-canonical bumps, creating duplicate "user" accounts where the program assumed one-per-user. This defeats per-user accounting, one-time-claim guards, and uniqueness invariants — e.g. claiming an airdrop multiple times.

## Fix pattern
```rust
#[account(
    init, payer = user, space = 8 + 32,
    seeds = [b"user", user.key().as_ref()],
    bump, // Anchor uses the canonical bump from find_program_address
)]
pub user_pda: Account<'info, UserData>,
// On later use, re-derive with the stored canonical bump:
#[account(seeds = [b"user", user.key().as_ref()], bump = user_pda.bump)]
```

## Detection heuristic
- `bump` values read from instruction arguments and passed to `create_program_address` / `Pubkey::create_program_address`
- `bump = <user_input>` rather than bare `bump` (canonical) or `bump = stored_bump`
- Any use of `create_program_address` without a preceding `find_program_address` canonical comparison

## References
- Coral sealevel-attacks — 7-bump-seed-canonicalization (https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/7-bump-seed-canonicalization)
- Solana program security course — bump seed canonicalization (https://solana.com/developers/courses/program-security/bump-seed-canonicalization)
- Anchor docs — PDA constraints (https://www.anchor-lang.com/docs/account-constraints)

## Real-world exploits (if any)
No single attributed public exploit; canonical-bump findings are common in public audits of claim/airdrop and per-user-account programs.
