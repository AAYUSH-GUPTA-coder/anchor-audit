# Rule 018: CPI Confused Deputy

**Severity:** High
**Category:** CPI

## Description
A program holds privileged authority (a PDA that owns a vault, mints a token, or controls an admin function) and exposes an instruction that performs a privileged CPI on a caller's behalf without checking that the caller is authorized for *that specific* resource. The program is the "deputy": it has authority, and the attacker confuses it into using that authority for the attacker's benefit.

## Vulnerable pattern
```rust
// Program PDA is the mint authority. This instruction mints to any
// destination the caller names, with no check on who may mint or how much.
pub fn mint_reward(ctx: Context<MintReward>, amount: u64) -> Result<()> {
    let seeds = &[b"mint_auth", &[ctx.accounts.config.bump]];
    token::mint_to(
        CpiContext::new_with_signer(/* ... */, &[&seeds[..]]),
        amount, // attacker-chosen, to an attacker-owned token account
    )?;
    Ok(())
}
```

## Why this is dangerous
The PDA signs the CPI, so from the token program's perspective the mint is fully authorized. The attacker calls `mint_reward` directly, names their own token account as the destination and an arbitrary amount, and the deputy mints unlimited tokens. The missing piece is authorization on the *caller* and bounds on the action.

## Fix pattern
```rust
pub fn mint_reward(ctx: Context<MintReward>, amount: u64) -> Result<()> {
    // Verify the caller is entitled to this reward and the amount is bounded
    require_keys_eq!(ctx.accounts.config.distributor, ctx.accounts.distributor.key());
    require!(amount <= ctx.accounts.reward.claimable, ErrorCode::ExceedsClaimable);
    ctx.accounts.reward.claimable -= amount;
    // ...then perform the signed mint CPI
    Ok(())
}
```
Require a `Signer` for the privileged role and bind the destination to validated state.

## Detection heuristic
- `invoke_signed` with a program-held PDA where the instruction lacks an authorization check on the caller
- Privileged CPIs (mint, transfer-from-vault, set-authority) whose amount/destination come straight from instruction args
- Instructions that expose the program's signing authority without `has_one`/`address`/signer gating tied to the affected resource

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Neodyme — Solana common pitfalls (https://neodyme.io/en/blog/solana_common_pitfalls/)
- Sec3 — Solana security best practices (https://www.sec3.dev/blog)

## Real-world exploits (if any)
The confused-deputy pattern underlies several DeFi drains where a vault/mint authority PDA was invocable without adequate caller authorization; it recurs as a critical finding in public audits.
