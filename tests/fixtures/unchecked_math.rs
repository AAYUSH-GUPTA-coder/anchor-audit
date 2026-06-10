// Fixture: Rule 023 + Rule 025 — unchecked arithmetic and precision loss
use anchor_lang::prelude::*;

const DENOM: u64 = 10_000;

#[account]
pub struct Pool {
    pub balance: u64,
    pub fee_bps: u16,
}

pub fn withdraw(pool: &mut Pool, amount: u64) {
    // Rule 025: division before multiplication — fee rounds to 0 for small amounts
    let fee = amount / DENOM * pool.fee_bps as u64;
    let payout = amount - fee;
    // Rule 023: unchecked subtraction may underflow in release builds
    pool.balance -= payout;
}
