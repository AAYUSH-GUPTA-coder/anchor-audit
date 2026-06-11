# anchor-audit

A security audit toolkit for [Anchor](https://www.anchor-lang.com/) programs on Solana. It ships two artifacts that share one 50-rule catalog:

- **A Claude Code skill** (`SKILL.md`) — invoke directly inside any Claude Code session; no API key required, no extra install.
- **A CLI** (`anchor-audit`) — runs the full catalog against a program directory via your own AI API key and produces a structured markdown or JSON report.

Both artifacts stay in sync automatically: improving a rule in `/rules/` immediately improves both the skill and the CLI.

> **Disclaimer:** `anchor-audit` is a first-pass triage aid, not a substitute for a professional human audit. See [Limitations](#limitations).

---

## Install — Claude Code skill

Add the skill to your Claude Code project:

```bash
# Manual install (works today)
git clone https://github.com/guptaaayush432/anchor-audit
cp SKILL.md ~/.claude/skills/anchor-audit.md
```

Once installed, trigger it inside any Claude Code session:

```
> audit my anchor program in ./programs/my-vault
> review this instruction for signer and CPI issues
> check my vault for unchecked arithmetic
```

Claude uses the skill automatically whenever you ask it to audit or review Solana/Anchor code.

---

## Install — CLI

Requires Node 20+ and an API key for any supported AI provider.

```bash
npm install -g anchor-audit
```

Set your API key (pick the provider you use):

```bash
export ANTHROPIC_API_KEY=sk-ant-...   # Anthropic (default)
export OPENAI_API_KEY=sk-...          # OpenAI
export GEMINI_API_KEY=...             # Google Gemini
export GROQ_API_KEY=gsk_...          # Groq (free tier available)
export OPENROUTER_API_KEY=sk-or-...  # OpenRouter
```

---

## Usage

### CLI

```bash
# Full audit, markdown report to stdout
anchor-audit ./programs/my-vault

# Save report to file
anchor-audit ./programs/my-vault --output AUDIT.md

# Run only specific rules
anchor-audit ./programs/my-vault --rules 001,017,030

# Show only high and critical findings
anchor-audit ./programs/my-vault --severity high

# JSON output
anchor-audit ./programs/my-vault --format json --output audit.json

# Verbose (shows rule batches as they run)
anchor-audit ./programs/my-vault --verbose

# Use a different provider or model
anchor-audit ./programs/my-vault --provider openai --model gpt-4o
anchor-audit ./programs/my-vault --provider google --model gemini-2.0-flash
anchor-audit ./programs/my-vault --provider groq   # free tier
anchor-audit ./programs/my-vault --provider custom --base-url http://localhost:11434/v1 --model llama3.1:8b --api-key ollama
```

### All flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output <path>` | stdout | Write report to file |
| `--rules <ids>` | all 50 | Comma-separated rule IDs, e.g. `001,017,030` |
| `--severity <min>` | low | Minimum severity: `critical \| high \| medium \| low` |
| `--format <fmt>` | `markdown` | `markdown` or `json` |
| `--verbose` | off | Print per-batch progress |
| `--api-key <key>` | env var | Override provider env var |
| `--provider <name>` | `anthropic` | `anthropic \| openai \| google \| groq \| openrouter \| custom` |
| `--model <id>` | per-provider | Override default model |
| `--base-url <url>` | — | Base URL for `--provider custom` (Ollama, LM Studio, etc.) |

**Default models per provider:**

| Provider | Default model |
|----------|--------------|
| `anthropic` | `claude-sonnet-4-6` |
| `openai` | `gpt-4o` |
| `google` | `gemini-2.0-flash` |
| `groq` | `llama-3.3-70b-versatile` |
| `openrouter` | `anthropic/claude-sonnet-4-6` |
| `custom` | `gpt-4o` |

> **Note on model quality:** Finding accuracy depends on the underlying model. Claude Opus 4.8 or GPT-4o will produce more precise, lower-noise results than smaller or free-tier models. All providers share the same rule prompts; only the model's ability to follow them differs.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Audit complete, no critical or high findings |
| `1` | Audit complete, at least one critical or high finding |
| `2` | Execution error (bad path, missing API key, etc.) |

---

## Rule catalog

50 rules across 8 categories. Each rule file contains a description, vulnerable pattern, fix pattern, detection heuristic, and references.

| ID | Rule | Severity | Category |
|----|------|----------|----------|
| [001](rules/001-missing-signer-check.md) | Missing signer check | Critical | Account validation |
| [002](rules/002-missing-owner-check.md) | Missing owner check | Critical | Account validation |
| [003](rules/003-missing-discriminator-check.md) | Missing discriminator check (type cosplay) | High | Account validation |
| [004](rules/004-account-substitution.md) | Account substitution | High | Account validation |
| [005](rules/005-sysvar-spoofing.md) | Sysvar spoofing | High | Account validation |
| [006](rules/006-missing-rent-exemption-check.md) | Missing rent-exemption check | Low | Account validation |
| [007](rules/007-account-aliasing.md) | Account aliasing (duplicate mutable accounts) | High | Account validation |
| [008](rules/008-uninitialized-account-use.md) | Uninitialized account use | High | Account validation |
| [009](rules/009-missing-mut-constraint.md) | Missing `mut` constraint | Medium | Account validation |
| [010](rules/010-missing-close-constraint.md) | Missing or improper close constraint | Medium | Account validation |
| [011](rules/011-pda-seed-collision.md) | PDA seed collision | High | PDA |
| [012](rules/012-missing-bump-validation.md) | Missing bump validation | Medium | PDA |
| [013](rules/013-non-canonical-bump-accepted.md) | Non-canonical bump accepted | High | PDA |
| [014](rules/014-predictable-pda.md) | Predictable / attacker-controlled PDA seeds | High | PDA |
| [015](rules/015-insecure-pda-across-upgrades.md) | Insecure PDA layout across upgrades | Medium | PDA |
| [016](rules/016-bump-mismatch.md) | Stored bump mismatch | Medium | PDA |
| [017](rules/017-arbitrary-cpi.md) | Arbitrary CPI (unvalidated target) | Critical | CPI |
| [018](rules/018-cpi-confused-deputy.md) | CPI confused deputy | High | CPI |
| [019](rules/019-missing-program-id-check-spl.md) | Missing program ID check on SPL CPIs | High | CPI |
| [020](rules/020-reentrancy-via-cpi.md) | Reentrancy via CPI | High | CPI |
| [021](rules/021-untrusted-callback.md) | Untrusted callback execution | High | CPI |
| [022](rules/022-cpi-with-attacker-accounts.md) | CPI invoked with attacker-controlled accounts | High | CPI |
| [023](rules/023-lamport-overflow.md) | Lamport arithmetic overflow / underflow | High | Math |
| [024](rules/024-token-amount-overflow.md) | Token amount arithmetic overflow | High | Math |
| [025](rules/025-precision-loss.md) | Precision loss (division before multiplication) | Medium | Math |
| [026](rules/026-rounding-direction.md) | Incorrect rounding direction | Medium | Math |
| [027](rules/027-token-decimal-mismatch.md) | Token decimal mismatch | Medium | Math |
| [028](rules/028-integer-cast-truncation.md) | Integer cast truncation | Medium | Math |
| [029](rules/029-off-by-one.md) | Off-by-one errors | Low | Math |
| [030](rules/030-missing-authorization.md) | Missing authorization on privileged instruction | Critical | Auth |
| [031](rules/031-reinitialization-attack.md) | Reinitialization attack | High | Auth |
| [032](rules/032-closed-account-revival.md) | Closed account revival | High | Auth |
| [033](rules/033-init-if-needed-misuse.md) | `init_if_needed` misuse | High | Auth |
| [034](rules/034-missing-has-one.md) | Missing `has_one` relationship enforcement | High | Auth |
| [035](rules/035-insecure-admin-transfer.md) | Insecure admin transfer (no acceptance handshake) | Medium | Auth |
| [036](rules/036-missing-pause-guards.md) | Missing pause / freeze guards | Low | Auth |
| [037](rules/037-clock-manipulation.md) | Clock / time-based logic without bounds | Medium | Auth |
| [038](rules/038-missing-address-validation.md) | Missing `address` validation on fixed-identity accounts | Medium | Constraints |
| [039](rules/039-constraint-evaluation-stage.md) | Constraint evaluation stage (pre- vs post-state) | Medium | Constraints |
| [040](rules/040-realloc-zero-init.md) | `realloc` without zero-init | Medium | Constraints |
| [041](rules/041-missing-payer-on-init.md) | `init` without `payer` (or wrong payer) | Low | Constraints |
| [042](rules/042-incorrect-space-allocation.md) | Incorrect `space` allocation | Medium | Constraints |
| [043](rules/043-account-vs-account-info.md) | `Account` vs `AccountInfo` misuse | High | Constraints |
| [044](rules/044-token-account-owner-unverified.md) | Token account owner unverified | High | SPL Token |
| [045](rules/045-token-mint-unverified.md) | Token mint unverified | High | SPL Token |
| [046](rules/046-ata-assumption-errors.md) | Associated token account assumption errors | Medium | SPL Token |
| [047](rules/047-token-program-id-hardcoded.md) | Token program ID hardcoded vs. validated | Medium | SPL Token |
| [048](rules/048-compute-budget-abuse.md) | Compute budget abuse (unbounded work) | Medium | Runtime |
| [049](rules/049-log-spam-dos.md) | Log spam / excessive logging DoS | Low | Runtime |
| [050](rules/050-stack-overflow-deep-cpi.md) | Stack / CPI depth exhaustion | Low | Runtime |

**Severity breakdown:** 4 Critical · 21 High · 17 Medium · 8 Low

---

## Limitations

`anchor-audit` is a **static, pattern-based triage tool** powered by an LLM. Understand what it does and does not catch before relying on it:

- **May miss:** business-logic vulnerabilities, economic/oracle attacks, cross-instruction state dependency bugs, and any issue that requires protocol-specific knowledge the model doesn't have.
- **May false-positive:** patterns that look like a rule but are safe in context (e.g. an `AccountInfo` that is genuinely verified elsewhere in the code).
- **Does not cover:** dynamic analysis, fuzzing, runtime behavior, or client-side (TypeScript/JavaScript) code.
- **Model-dependent:** finding quality varies by provider and model. A strong model (Claude Opus, GPT-4o) produces more precise results than smaller or free-tier models.

**Never treat a clean `anchor-audit` report as authorization to deploy to mainnet.** Always confirm each finding manually, and get an independent professional audit before any production deployment involving real funds.

---

## Contributing

### Adding or improving a rule

1. Copy the template from [rules/README.md](rules/README.md) into a new file `rules/NNN-kebab-name.md`
2. Fill in all seven sections — description, vulnerable pattern, why it's dangerous, fix pattern, detection heuristic, references, real-world exploits
3. All content must be sourced (Neodyme, Sec3, Helius, Anchor book, Cyfrin Updraft, public audit reports) and cited in References
4. Add a row to [rules/INDEX.md](rules/INDEX.md)
5. Run `npm test` — the rules test suite validates file count, template sections, and severity format

### Running tests locally

```bash
npm install
npm test          # 272 unit tests
npm run typecheck
npm run lint
```

### Reporting issues

Open an issue at [github.com/guptaaayush432/anchor-audit/issues](https://github.com/guptaaayush432/anchor-audit/issues).

---

## License

[MIT](./LICENSE) — Aayush Gupta, 2026
