# Rule catalog

One markdown file per rule, named `NNN-kebab-case-name.md` (e.g. `001-missing-signer-check.md`). The full list with severities lives in [INDEX.md](./INDEX.md).

The catalog is consumed by both the Claude Code skill ([SKILL.md](../SKILL.md)) and the CLI (`cli/src/rules-loader.ts`), so every file must follow this exact template:

````markdown
# Rule NNN: <Title>

**Severity:** Critical | High | Medium | Low
**Category:** Account validation | PDA | CPI | Math | Auth | Constraints | SPL Token | Runtime

## Description
One paragraph explaining the vulnerability and why it matters.

## Vulnerable pattern
```rust
// Minimal Rust/Anchor snippet showing the bug
```

## Why this is dangerous
Explain attacker action and impact in 2 to 4 sentences.

## Fix pattern
```rust
// Minimal Rust/Anchor snippet showing the corrected code
```

## Detection heuristic
Bullet list of things an agent should look for in source code to flag this rule.

## References
- Source 1 (URL)
- Source 2 (URL)

## Real-world exploits (if any)
Optional: brief mention of public exploits matching this pattern.
````

Content must be sourced (Neodyme, Sec3, Helius, Solana Cookbook, Cyfrin Updraft, the Anchor book, public audit reports) and cited in the References section — never invented.
