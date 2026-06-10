// Fixture: Rule 001 — missing signer check
// The authority account is AccountInfo instead of Signer; ownership is
// compared by key but a signature is never required.
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct SetConfig<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    /// CHECK: compared by key below
    pub authority: AccountInfo<'info>,
}

pub fn set_config(ctx: Context<SetConfig>, value: u64) -> Result<()> {
    require_keys_eq!(ctx.accounts.config.admin, ctx.accounts.authority.key());
    ctx.accounts.config.value = value;
    Ok(())
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub value: u64,
}
