# Rule 006: Missing Rent-Exemption Check

**Severity:** Low
**Category:** Account validation

## Description
Accounts created or resized through raw system-program calls must be funded to the rent-exempt minimum for their size. Anchor's `init` and `realloc` handle this automatically, but manual `create_account` / `transfer` + `allocate` flows that compute lamports themselves can under-fund the account. The runtime rejects most non-exempt account creation today, but programs that accept *existing* accounts and assume durable state should still verify exemption rather than assume it.

## Vulnerable pattern
```rust
// Manual account creation with a hardcoded lamport amount
let create_ix = system_instruction::create_account(
    payer.key,
    new_account.key,
    1_000_000, // guessed value — not Rent::get()?.minimum_balance(space)
    space as u64,
    program_id,
);
invoke(&create_ix, &[payer.clone(), new_account.clone()])?;
```

## Why this is dangerous
Under-funded accounts fail at runtime in ways that surface as hard-to-diagnose errors, and lamport-balance assumptions elsewhere in the program (e.g. treating every account's balance above some floor as withdrawable) can double-count the rent reserve. Draining an account below its rent-exempt minimum while leaving it open also makes subsequent writes fail.

## Fix pattern
```rust
let rent = Rent::get()?;
let lamports = rent.minimum_balance(space);
let create_ix = system_instruction::create_account(
    payer.key, new_account.key, lamports, space as u64, program_id,
);
invoke(&create_ix, &[payer.clone(), new_account.clone()])?;
```
In Anchor, prefer `#[account(init, payer = payer, space = 8 + Data::INIT_SPACE)]`, which funds exemption automatically.

## Detection heuristic
- `system_instruction::create_account` with a literal/derived lamport value not based on `Rent::minimum_balance`
- Lamport withdrawals that drain an account to zero or below `Rent::minimum_balance(data_len)` while the account stays open
- Programs reading `account.lamports()` as "user balance" without subtracting the rent reserve

## References
- Solana docs — rent (https://solana.com/docs/core/fees#rent)
- Anchor docs — account constraints, init (https://www.anchor-lang.com/docs/account-constraints)
- Helius — A Hitchhiker's Guide to Solana Program Security (https://www.helius.dev/blog/a-hitchhikers-guide-to-solana-program-security)

## Real-world exploits (if any)
No public exploit attributed to this pattern; it appears in audits as a robustness/informational finding that compounds with lamport-accounting bugs (see Rule 023).
