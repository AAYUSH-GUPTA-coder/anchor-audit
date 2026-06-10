// !! WARNING: This program is INTENTIONALLY INSECURE for educational purposes.
// !! It was written to demonstrate Anchor security anti-patterns and is used
// !! as the regression target for anchor-audit. NEVER deploy to any network.
use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("VuLnErAbLeVauLt111111111111111111111111111111");

const FEE_DENOMINATOR: u64 = 10_000;
const MAX_FEE_BPS: u16 = 1_000;

#[program]
pub mod vulnerable_vault {
    use super::*;

    /// Initialize the vault state.
    ///
    /// Sets up admin, fee rate, and the vault PDA bump. Any payer may call
    /// this instruction; the admin is supplied as an argument.
    pub fn initialize_vault(
        ctx: Context<InitializeVault>,
        admin: Pubkey,
        fee_bps: u16,
        vault_bump: u8,
    ) -> Result<()> {
        require!(fee_bps <= MAX_FEE_BPS, VaultError::FeeTooHigh);

        let vault = &mut ctx.accounts.vault_state;
        vault.admin = admin;
        vault.fee_bps = fee_bps;
        vault.total_deposited = 0;
        vault.vault_bump = vault_bump;
        vault.reward_rate = 100;
        Ok(())
    }

    /// Transfer admin authority to a new address.
    pub fn set_admin(ctx: Context<SetAdmin>, new_admin: Pubkey) -> Result<()> {
        ctx.accounts.vault_state.admin = new_admin;
        Ok(())
    }

    /// Create a per-user position account.
    ///
    /// The caller supplies the PDA bump that was found off-chain.
    pub fn create_position(ctx: Context<CreatePosition>, bump: u8) -> Result<()> {
        let pos = &mut ctx.accounts.user_position;
        pos.owner = ctx.accounts.user.key();
        pos.deposited = 0;
        pos.reward_debt = 0;
        pos.bump = bump;
        Ok(())
    }

    /// Deposit tokens into the vault.
    ///
    /// Transfers `amount` from the caller's token account to the vault's token
    /// account and records the deposit in the user position.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        require!(amount > 0, VaultError::ZeroAmount);

        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.user_token.to_account_info(),
                to: ctx.accounts.vault_token.to_account_info(),
                authority: ctx.accounts.user.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;

        ctx.accounts.vault_state.total_deposited += amount;
        ctx.accounts.user_position.deposited += amount;
        Ok(())
    }

    /// Withdraw tokens from the vault.
    ///
    /// Deducts a fee and transfers the remainder to the caller's token account.
    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault_fee_bps = ctx.accounts.vault_state.fee_bps;
        let vault_bump = ctx.accounts.vault_state.vault_bump;

        let pos = &mut ctx.accounts.user_position;
        require!(pos.deposited >= amount, VaultError::InsufficientFunds);

        let fee = amount / FEE_DENOMINATOR * vault_fee_bps as u64;
        let payout = amount - fee;

        pos.deposited -= amount;

        let seeds: &[&[u8]] = &[b"vault", &[vault_bump]];
        let signer_seeds = &[seeds];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.user_token.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, payout)?;
        Ok(())
    }

    /// Collect accumulated fees from the vault.
    ///
    /// Transfers `amount` from the vault token account to the fee recipient.
    pub fn collect_fees(ctx: Context<CollectFees>, amount: u64) -> Result<()> {
        let vault_data = ctx.accounts.vault_state.try_borrow_data()?;
        // Read the stored bump from the raw account bytes (offset 42).
        let vault_bump = vault_data[42];
        drop(vault_data);

        let seeds: &[&[u8]] = &[b"vault", &[vault_bump]];
        let signer_seeds = &[seeds];
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.vault_token.to_account_info(),
                to: ctx.accounts.fee_recipient.to_account_info(),
                authority: ctx.accounts.vault_authority.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, amount)?;
        Ok(())
    }

    /// Close a user position and recover its rent lamports.
    pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        let pos_info = ctx.accounts.user_position.to_account_info();
        let user_info = ctx.accounts.user.to_account_info();
        **user_info.try_borrow_mut_lamports()? += pos_info.lamports();
        **pos_info.try_borrow_mut_lamports()? = 0;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Account state structs
// ---------------------------------------------------------------------------

#[account]
#[derive(InitSpace)]
pub struct VaultState {
    pub admin: Pubkey,
    pub fee_bps: u16,
    pub total_deposited: u64,
    pub vault_bump: u8,
    pub reward_rate: u64,
}

#[account]
#[derive(InitSpace)]
pub struct UserPosition {
    pub owner: Pubkey,
    pub deposited: u64,
    pub reward_debt: u64,
    pub bump: u8,
}

// ---------------------------------------------------------------------------
// Instruction contexts
// ---------------------------------------------------------------------------

#[derive(Accounts)]
#[instruction(admin: Pubkey, fee_bps: u16, vault_bump: u8)]
pub struct InitializeVault<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + VaultState::INIT_SPACE,
        seeds = [b"vault"],
        bump,
    )]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetAdmin<'info> {
    #[account(mut)]
    pub vault_state: Account<'info, VaultState>,
    pub caller: Signer<'info>,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct CreatePosition<'info> {
    #[account(
        init,
        payer = user,
        space = 8 + UserPosition::INIT_SPACE,
        seeds = [b"position", user.key().as_ref()],
        bump,
    )]
    pub user_position: Account<'info, UserPosition>,
    #[account(mut)]
    pub user: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, seeds = [b"vault"], bump = vault_state.vault_bump)]
    pub vault_state: Account<'info, VaultState>,
    pub user_position: Account<'info, UserPosition>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    pub user: Signer<'info>,
    /// CHECK: token program for transfers
    pub token_program: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, seeds = [b"vault"], bump = vault_state.vault_bump)]
    pub vault_state: Account<'info, VaultState>,
    #[account(mut)]
    pub user_position: Account<'info, UserPosition>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub user_token: Account<'info, TokenAccount>,
    /// CHECK: vault PDA signing authority
    #[account(seeds = [b"vault"], bump = vault_state.vault_bump)]
    pub vault_authority: AccountInfo<'info>,
    pub user: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct CollectFees<'info> {
    /// CHECK: vault global state — not type-checked
    pub vault_state: AccountInfo<'info>,
    #[account(mut)]
    pub vault_token: Account<'info, TokenAccount>,
    #[account(mut)]
    pub fee_recipient: Account<'info, TokenAccount>,
    /// CHECK: vault signing authority
    pub vault_authority: AccountInfo<'info>,
    pub caller: Signer<'info>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut)]
    pub user_position: Account<'info, UserPosition>,
    #[account(mut)]
    pub user: Signer<'info>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[error_code]
pub enum VaultError {
    #[msg("Fee exceeds the maximum allowed value")]
    FeeTooHigh,
    #[msg("Amount must be greater than zero")]
    ZeroAmount,
    #[msg("Insufficient deposited balance for this withdrawal")]
    InsufficientFunds,
}
