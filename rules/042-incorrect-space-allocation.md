# Rule 042: Incorrect `space` Allocation

**Severity:** Medium
**Category:** Constraints

## Description
The `space` value in an `init` constraint must exactly accommodate the 8-byte discriminator plus the serialized size of every field, including the worst-case length of variable-length fields (`String`, `Vec<T>`). Too small and writes either fail or, for fixed layouts computed by hand, corrupt adjacent data; mis-estimating variable-length capacity strands the account at a size that can't hold its intended contents.

## Vulnerable pattern
```rust
#[account]
pub struct Profile {
    pub authority: Pubkey, // 32
    pub name: String,      // 4 (len prefix) + N bytes
    pub friends: Vec<Pubkey>, // 4 + 32 * count
}

#[account(init, payer = user, space = 8 + 32)] // forgot name + friends
pub profile: Account<'info, Profile>,
```

## Why this is dangerous
Under-allocating means later writes that grow the `String`/`Vec` fail (bricking updates) or require a separate realloc the program never performs. Hand-computed sizes that are wrong can also misalign serialization. Over-allocating wastes rent but is safe; under-allocating is the security/robustness problem, sometimes blocking critical paths like updating a record needed for withdrawal.

## Fix pattern
```rust
#[account]
#[derive(InitSpace)] // Anchor computes fixed-size contribution automatically
pub struct Profile {
    pub authority: Pubkey,
    #[max_len(32)]            // cap variable-length fields explicitly
    pub name: String,
    #[max_len(50)]
    pub friends: Vec<Pubkey>,
}

#[account(init, payer = user, space = 8 + Profile::INIT_SPACE)]
pub profile: Account<'info, Profile>,
```

## Detection heuristic
- Hand-written `space = 8 + <number>` literals not derived from `INIT_SPACE` / a documented size calc
- Variable-length fields (`String`, `Vec`) with no `#[max_len]` and no accounting in `space`
- `space` smaller than the sum of field sizes (32 per Pubkey, 8 per u64, 1 per bool/u8, 4 + content for collections)
- Structs that gained fields without a corresponding `space` update

## References
- Anchor docs — space and InitSpace (https://www.anchor-lang.com/docs/space)
- The Anchor Book — account size (https://book.anchor-lang.com/anchor_in_depth/the_accounts_struct.html)
- Sec3 — account sizing pitfalls (https://www.sec3.dev/blog)

## Real-world exploits (if any)
No single attributed public exploit; incorrect space is a common correctness/availability finding, occasionally bricking update or close paths.
