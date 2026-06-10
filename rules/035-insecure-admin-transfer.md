# Rule 035: Insecure Admin Transfer (No Acceptance Handshake)

**Severity:** Medium
**Category:** Auth

## Description
Transferring a privileged role (admin, owner, upgrade authority) in a single instruction that immediately sets the new authority is fragile: a typo or a wrong/uncontrolled address permanently locks out administration with no recovery. The safe pattern is a two-step handshake — the current admin *nominates* a pending admin, and the nominee must *accept* — so an unusable address can never take ownership.

## Vulnerable pattern
```rust
pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
    // One-step: if new_admin is wrong or unowned, admin control is lost forever
    ctx.accounts.config.admin = new_admin;
    Ok(())
}
```

## Why this is dangerous
A single-step transfer to a mistyped address, an exchange deposit address, or a contract that can't sign irreversibly bricks every admin-gated function (pause, upgrade, fee changes, emergency withdrawal). There is no way to prove the new admin can actually sign before handing over control. This is a self-inflicted-loss and incident-response risk, not a direct theft vector.

## Fix pattern
```rust
pub fn nominate_admin(ctx: Context<AdminOnly>, candidate: Pubkey) -> Result<()> {
    ctx.accounts.config.pending_admin = candidate;
    Ok(())
}

pub fn accept_admin(ctx: Context<AcceptAdmin>) -> Result<()> {
    require_keys_eq!(ctx.accounts.config.pending_admin, ctx.accounts.candidate.key());
    ctx.accounts.config.admin = ctx.accounts.candidate.key(); // candidate must sign
    ctx.accounts.config.pending_admin = Pubkey::default();
    Ok(())
}
```
The `accept_admin` context requires `candidate: Signer`, proving control.

## Detection heuristic
- Admin/owner/authority fields reassigned in one instruction from an argument, with no `pending_*` field
- Absence of a paired nominate/accept (or propose/claim) instruction set
- Upgrade-authority or critical-role transfers without a signature from the incoming party
- No `Pubkey::default()` / sanity guard on the new authority value

## References
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)
- Sec3 — privileged role management (https://www.sec3.dev/blog)
- OpenZeppelin — Ownable2Step (concept reference) (https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable2Step)

## Real-world exploits (if any)
No theft exploit; single-step authority transfers have caused permanent loss of admin control (bricked protocols) across ecosystems. Standard medium audit finding.
