# anchor-audit

A security audit toolkit for [Anchor](https://www.anchor-lang.com/) smart contracts on Solana.

Anchor programs handle real money on-chain. A single missing signer check or unchecked arithmetic operation can drain a protocol entirely. `anchor-audit` gives developers a fast, structured first pass over their code before it ships.

> **Disclaimer:** `anchor-audit` is a triage aid, not a substitute for a professional human audit. See [Limitations](#limitations).

---

## What is anchor-audit?

`anchor-audit` checks your Rust/Anchor source files against a catalog of **50 known Solana security rules** - things like missing signer checks, arbitrary CPI targets, arithmetic overflows, and reinitialization attacks. It sends your code to an AI model that reads each rule and flags any matching patterns, then formats the results into a structured report.

It ships as two tools that share the same 50-rule catalog:

| Tool | What it is | When to use it |
|------|-----------|----------------|
| **Claude Code Skill** | A prompt skill for Claude Code | When you're already in a Claude Code session and want a quick review |
| **CLI (`anchor-audit`)** | A command-line tool | When you want a full automated report you can save, diff, and share |

Both tools stay in sync: when a rule is improved in `/rules/`, both the skill and the CLI benefit automatically.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Claude Code Skill](#claude-code-skill)
- [CLI Setup](#cli-setup)
  - [Cloud Providers](#cloud-providers)
  - [Local Models](#local-models-no-api-key-no-cost)
- [Running an Audit](#running-an-audit)
- [Understanding the Flags](#understanding-the-flags)
- [Reading the Report](#reading-the-report)
- [Performance Guide](#performance-guide)
- [Rule Catalog](#rule-catalog)
- [Limitations](#limitations)
- [Contributing](#contributing)

---

## Quick Start

**Option A - Claude Code Skill (fastest):**
```bash
git clone https://github.com/guptaaayush432/anchor-audit
cp anchor-audit/SKILL.md ~/.claude/skills/anchor-audit.md
# Then in any Claude Code session: "audit my program in ./programs/my-vault"
```

**Option B - CLI with a cloud provider:**
```bash
npm install -g anchor-audit

# Set your API key for whichever provider you use
export ANTHROPIC_API_KEY=sk-ant-...   # Anthropic (default)
export OPENAI_API_KEY=sk-...          # OpenAI
export GROQ_API_KEY=gsk_...           # Groq (free tier)

# Basic run - uses Anthropic claude-sonnet-4-6 by default
anchor-audit ./programs/my-vault

# Show progress as each rule batch is processed
anchor-audit ./programs/my-vault --verbose

# Use a different provider or model
anchor-audit ./programs/my-vault --provider openai --model gpt-4o
anchor-audit ./programs/my-vault --provider groq

# Only check critical and high severity rules (faster)
anchor-audit ./programs/my-vault --severity high

# Deeper analysis with more output per finding
anchor-audit ./programs/my-vault --effort high

# Fast triage - high severity rules only, low token budget
anchor-audit ./programs/my-vault --severity high --effort low

# Save report to a file
anchor-audit ./programs/my-vault --output AUDIT.md
```

**Option C - CLI with Ollama (free, runs locally):**
```bash
npm install -g anchor-audit
ollama pull llama3.1:8b
anchor-audit ./programs/my-vault --provider ollama --effort low
# Change the model and reasoning effort accordingly
```

---

## Claude Code Skill

The Claude Code Skill lets you audit Anchor programs directly inside a Claude Code session - no API key needed beyond your existing Claude/Codex subscription, no extra installation beyond copying one file.

### Install

```bash
git clone https://github.com/guptaaayush432/anchor-audit
cp anchor-audit/SKILL.md ~/.claude/skills/anchor-audit.md
```

### How to use it

Once installed, Claude/Codex picks up the skill automatically whenever you ask it to review Anchor code. Just describe what you want in plain English:

```
> audit my anchor program in ./programs/my-vault
> review the withdraw instruction for authorization issues
> check this code for unchecked arithmetic
> does my vault have any CPI safety issues?
> look for missing signer checks in programs/staking/src/lib.rs
```

Claude/Codex will read your source files, apply the 50-rule catalog, and respond with a structured list of findings.

### When to use the Skill vs the CLI

| | Skill | CLI |
|--|-------|-----|
| Requires separate API key | No | Yes (or local model) |
| Interactive follow-up questions | Yes | No |
| Saves a report file automatically | No | Yes |
| Full 50-rule batch scan | Depends on context | Always |
| Good for | Quick reviews while coding | Full audits before shipping |

---

## CLI Setup

### Requirements

- Node.js 20 or later (`node --version` to check)
- An AI provider - cloud (needs API key) or local (needs Ollama/LM Studio/vLLM running)

### Install

```bash
npm install -g anchor-audit
```

Verify it works:

```bash
anchor-audit --help
```

---

## Cloud Providers

Cloud providers are the easiest to start with and produce the most accurate results. You sign up for an API key, set an environment variable, and you're done.

### Anthropic (default, recommended)

Best overall accuracy for security auditing. Uses `claude-sonnet-4-6` by default. Change Accordingly.

```bash
export ANTHROPIC_API_KEY=sk-ant-...
anchor-audit ./programs/my-vault
```

**Where to get a key:** [console.anthropic.com](https://console.anthropic.com)

For the deepest analysis, use a more powerful model:

```bash
anchor-audit ./programs/my-vault --model claude-opus-4-8
```

### OpenAI (ChatGPT)

```bash
export OPENAI_API_KEY=sk-...
anchor-audit ./programs/my-vault --provider openai
anchor-audit ./programs/my-vault --provider openai --model gpt-4o
```

**Where to get a key:** [platform.openai.com](https://platform.openai.com)

### Google Gemini

```bash
export GEMINI_API_KEY=...
anchor-audit ./programs/my-vault --provider google
anchor-audit ./programs/my-vault --provider google --model gemini-2.0-flash
```

**Where to get a key:** [aistudio.google.com](https://aistudio.google.com)

### Groq

Groq offers a generous free tier - a good way to try the tool at no cost with a cloud model.

```bash
export GROQ_API_KEY=gsk_...
anchor-audit ./programs/my-vault --provider groq
```

**Where to get a key:** [console.groq.com](https://console.groq.com)

### OpenRouter (access 100+ models with one key)

OpenRouter is a single API that routes to Anthropic, OpenAI, Meta, Mistral, and many others. Useful if you want to compare results across models.

```bash
export OPENROUTER_API_KEY=sk-or-...
anchor-audit ./programs/my-vault --provider openrouter
anchor-audit ./programs/my-vault --provider openrouter --model meta-llama/llama-3.3-70b-instruct
anchor-audit ./programs/my-vault --provider openrouter --model google/gemini-2.0-flash
```

**Where to get a key:** [openrouter.ai](https://openrouter.ai)

---

## Local Models (no API key, no cost)

Local models run entirely on your machine. No data leaves your computer, there are no API costs, and you can audit private code without sending it to a third party.

The trade-off is speed and accuracy - local models are slower and may miss subtle issues that a large cloud model would catch. See [Performance Guide](#performance-guide) for tips.

### Ollama

[Ollama](https://ollama.com) is the easiest way to run local models on macOS, Linux, or Windows.

**Step 1 - Install Ollama:**
```bash
# macOS
brew install ollama

# Or download from https://ollama.com
```

**Step 2 - Pull a model:**
```bash
# Small and fast (good for quick checks)
ollama pull llama3.1:8b

# Larger and more accurate (slower)
ollama pull qwen2.5-coder:32b
ollama pull llama3.3:70b
```

**Step 3 - Start the Ollama server** (it may already be running):
```bash
ollama serve
```

**Step 4 - Run the audit:**
```bash
# No API key needed
anchor-audit ./programs/my-vault --provider ollama --model llama3.1:8b
```

To use a non-default port:
```bash
anchor-audit ./programs/my-vault --provider ollama \
  --base-url http://localhost:5000/v1 \
  --model llama3.1:8b
```

### LM Studio

[LM Studio](https://lmstudio.ai) provides a desktop GUI for downloading and running local models.

**Step 1** - Download and open LM Studio  
**Step 2** - Download a model from the Discover tab (e.g. Mistral 7B, Qwen 2.5)  
**Step 3** - Go to the Local Server tab and click **Start Server**  
**Step 4** - Run the audit:

```bash
# LM Studio's server runs on port 1234 by default
anchor-audit ./programs/my-vault --provider lmstudio --model local-model
```

The `--model local-model` value is a placeholder - LM Studio uses whichever model is currently loaded in its UI.

### vLLM

[vLLM](https://vllm.ai) is a high-throughput inference engine for production-grade local deployments.

```bash
# Start vLLM server first (example)
python -m vllm.entrypoints.openai.api_server \
  --model mistralai/Mistral-7B-Instruct-v0.3 \
  --port 8000

# Then run the audit
anchor-audit ./programs/my-vault --provider vllm --model mistralai/Mistral-7B-Instruct-v0.3
```

### Custom endpoint

Any server that speaks the OpenAI chat completions API format works with `--provider custom`:

```bash
anchor-audit ./programs/my-vault \
  --provider custom \
  --base-url http://192.168.1.10:8080/v1 \
  --model my-model-name
```

---

## Running an Audit

### Basic usage

```bash
# Print findings to the terminal
anchor-audit ./programs/my-vault

# Save to a file
anchor-audit ./programs/my-vault --output AUDIT.md

# Show progress as each rule batch is sent to the model
anchor-audit ./programs/my-vault --verbose
```

### Filter by severity

`--severity` controls **which rules are checked**. Rules below the chosen level are skipped entirely - fewer rules means fewer batches, which means a faster run.

```
--severity critical   →  4 rules  →  1 batch   (fastest)
--severity high       →  25 rules →  5 batches
--severity medium     →  42 rules →  9 batches
--severity low        →  50 rules →  10 batches (default, slowest)
```

```bash
# Only check the 4 most critical rules (missing signer, owner, auth, arbitrary CPI)
anchor-audit ./programs/my-vault --severity critical

# Check critical + high rules (covers the most dangerous 25 rules)
anchor-audit ./programs/my-vault --severity high

# Check everything (default)
anchor-audit ./programs/my-vault
```

### Control analysis depth

`--effort` controls **how many output tokens the model is allowed to generate per batch**. More tokens means the model can write longer, more detailed findings - but each batch takes longer.

| Effort | Max tokens | Best for |
|--------|-----------|----------|
| `low` | 2,048 | Local models, fast triage |
| `medium` | 4,096 | Default, balanced |
| `high` | 8,192 | Cloud models, thorough reports |

```bash
# Fast triage - good for local models or quick CI checks
anchor-audit ./programs/my-vault --effort low --severity high

# Deep analysis - good for pre-release audits with a cloud model
anchor-audit ./programs/my-vault --effort high
```

### Run only specific rules

If you already know which issues to look for, skip the rest:

```bash
# Check only for missing signer (001), arbitrary CPI (017), and missing auth (030)
anchor-audit ./programs/my-vault --rules 001,017,030
```

### JSON output

```bash
# Print JSON to stdout
anchor-audit ./programs/my-vault --format json

# Save JSON to file
anchor-audit ./programs/my-vault --format json --output audit.json
```

### Combining flags

```bash
# Recommended for local models: fast, focused on high-severity issues
anchor-audit ./programs/my-vault \
  --provider ollama --model llama3.1:8b \
  --severity high --effort low \
  --verbose

# Recommended for pre-release audit with Anthropic
anchor-audit ./programs/my-vault \
  --provider anthropic --model claude-opus-4-8 \
  --effort high \
  --output AUDIT_$(date +%Y-%m-%d).md
```

---

## Understanding the Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--provider <name>` | `anthropic` | Which AI provider to use. See [Providers](#cloud-providers) |
| `--model <id>` | per-provider | Override the default model for the chosen provider |
| `--api-key <key>` | env var | Pass your API key inline instead of via environment variable |
| `--base-url <url>` | per-provider | Override the server URL (useful for local models on non-default ports) |
| `--severity <level>` | `low` | Only check rules at this level or above. Does not filter the *output* - it skips rules entirely |
| `--effort <level>` | `medium` | How many tokens the model can use per batch. Higher = more detail, slower |
| `--rules <ids>` | all 50 | Comma-separated list of rule IDs to run, e.g. `001,017,030` |
| `--format <fmt>` | `markdown` | Output format: `markdown` or `json` |
| `--output <path>` | - | Write the report to this file in addition to the auto-saved copy |
| `--verbose` | off | Print each batch as it's sent to the model - useful for tracking progress |

**Provider defaults:**

| Provider | Type | Default model | API key env var |
|----------|------|--------------|-----------------|
| `anthropic` | Cloud | `claude-sonnet-4-6` | `ANTHROPIC_API_KEY` |
| `openai` | Cloud | `gpt-4o` | `OPENAI_API_KEY` |
| `google` | Cloud | `gemini-2.0-flash` | `GEMINI_API_KEY` |
| `groq` | Cloud | `llama-3.3-70b-versatile` | `GROQ_API_KEY` |
| `openrouter` | Cloud | `anthropic/claude-sonnet-4-6` | `OPENROUTER_API_KEY` |
| `ollama` | Local | `llama3.1:8b` | none required |
| `lmstudio` | Local | `local-model` | none required |
| `vllm` | Local | `local-model` | none required |
| `custom` | Either | `gpt-4o` | `OPENAI_API_KEY` |

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Audit complete - no critical or high findings |
| `1` | Audit complete - at least one critical or high finding was found |
| `2` | Error - bad path, missing API key, connection refused, etc. |

Exit code `1` is useful in CI: add `anchor-audit` as a pipeline step and it will block the build if critical issues are found.

---

## Reading the Report

Every audit produces a markdown report with three sections:

### Audit Metadata

At the top of every report, you'll see exactly how and when it was generated:

```
| Field          | Value                          |
|----------------|--------------------------------|
| Date           | 2026-06-19                     |
| Time           | 14:30:15 UTC                   |
| Model          | claude-sonnet-4-6              |
| Provider       | anthropic                      |
| Effort         | medium                         |
| CLI Version    | v0.1.0                         |
| Project        | my-vault                       |
| Git Branch     | main                           |
| Git Commit     | a1b2c3d                        |
| OS             | Darwin 25.0.0 (arm64)          |
| Duration       | 42.3s                          |
| Files Analyzed | 3                              |
| Total Findings | 7                              |
```

### Summary table

A quick count of findings by severity so you know at a glance how serious the results are:

```
| Severity | Count |
|----------|-------|
| Critical | 2     |
| High     | 3     |
| Medium   | 1     |
| Low      | 1     |
| Total    | 7     |
```

### Findings

Each finding looks like this:

```
### [CRITICAL] Rule 001: Missing signer check in set_admin

**File:** `src/lib.rs:42`

**Description:** The `authority` account is passed as `AccountInfo` but is
never verified as a signer. Any account can be passed here, letting an
attacker call set_admin with a fake authority.

**Vulnerable code:**
pub authority: AccountInfo<'info>,

**Recommendation:** Change `AccountInfo<'info>` to `Signer<'info>`. Anchor
will then automatically verify the account signed the transaction.

**Reference:** rules/001-missing-signer-check.md
```

### Auto-saved reports

Every run automatically saves a timestamped copy to a `reports/` folder so you never lose a result:

```
reports/
  my-vault-2026-06-19T14-30-15Z.md
  my-vault-2026-06-20T09-12-44Z.md
```

The `reports/` directory is gitignored by default. Use `--output` to save a named copy in a specific location as well.

---

## Performance Guide

### Cloud models

Cloud models are fast and accurate. The full 50-rule audit typically finishes in **1–3 minutes**. No special configuration needed beyond an API key.

### Local models

Local models run on your hardware. Speed depends on your machine's CPU, RAM, and whether you have a GPU:

| Hardware | 8B model speed | 50-rule audit time |
|----------|---------------|-------------------|
| MacBook (Apple Silicon) | 30–60 tok/s | ~5–10 min |
| Gaming GPU (RTX 4090) | 100–150 tok/s | ~2–4 min |
| CPU only | 5–15 tok/s | 20–40 min |

**Tips for faster local audits:**

```bash
# 1. Use --effort low to halve the output token budget
anchor-audit ./programs/my-vault --provider ollama --effort low

# 2. Use --severity high to cut from 10 batches to 5 batches
anchor-audit ./programs/my-vault --provider ollama --effort low --severity high

# 3. Use --severity critical for a 1-batch quick check (4 rules only)
anchor-audit ./programs/my-vault --provider ollama --severity critical

# 4. Use a smaller model - 3B or 4B models are 2–3x faster than 8B
ollama pull llama3.2:3b
anchor-audit ./programs/my-vault --provider ollama --model llama3.2:3b --effort low
```

**Recommended combinations:**

| Goal | Command |
|------|---------|
| Fastest possible check (local) | `--provider ollama --severity critical --effort low` |
| Balanced local scan | `--provider ollama --severity high --effort low` |
| Full local scan (patient) | `--provider ollama --effort low` |
| Best accuracy (cloud) | `--provider anthropic --model claude-opus-4-8 --effort high` |
| Free cloud option | `--provider groq --severity high` |

> **Note on accuracy:** The same rules are sent to every model. A stronger model (Claude Opus, GPT-4o) will find more real issues and produce fewer false positives than a smaller local model. Use local models for quick iterative checks during development, and a strong cloud model for pre-release audits.

---

## Rule Catalog

50 rules across 8 categories. Click any rule ID to read the full description, vulnerable pattern, fix pattern, and references.

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

`anchor-audit` is a **static, pattern-based triage tool**. It is useful for catching known vulnerability classes quickly, but it has real limits you need to understand before relying on it.

**What it may miss:**
- Business-logic vulnerabilities specific to your protocol's design
- Economic attacks (price manipulation, oracle exploits, flash loan vectors)
- Bugs that only appear when multiple instructions are called in sequence
- Issues in client-side TypeScript/JavaScript code

**What it may get wrong:**
- False positives - patterns that look like a rule but are safe in context (e.g. an `AccountInfo` that is verified elsewhere)
- False negatives - real issues the model fails to recognize because the code pattern is unusual

**What it does not cover:**
- Dynamic analysis or fuzzing
- Runtime behavior
- Cross-program interaction analysis beyond CPI rule patterns

**Model accuracy varies:**

The same 50 rules are sent to every model. A larger, more capable model produces more accurate findings. Expect:
- Strong cloud models (Claude Opus, GPT-4o): high precision, few false positives
- Smaller local models (7B–8B): more false positives, may miss subtle issues
- Free cloud tiers: varies; Groq's Llama models perform well for their cost

**Never deploy to mainnet based solely on a clean `anchor-audit` report.** Always review findings manually, and get an independent professional audit before any program that holds real funds goes live.

---

## Contributing

### Adding or improving a rule

Each rule is a single markdown file in `/rules/` following a fixed template with seven required sections: description, vulnerable pattern, why it's dangerous, fix pattern, detection heuristic, references, and real-world exploits.

1. Copy the template from [rules/README.md](rules/README.md) into a new file: `rules/NNN-kebab-name.md`
2. Fill in all seven sections - no section may be left blank
3. Cite your sources in the References section (Neodyme, Sec3, Helius, Anchor book, Cyfrin Updraft, public audit reports)
4. Add a row to [rules/INDEX.md](rules/INDEX.md)
5. Run the test suite - it validates every rule file automatically

### Running tests locally

```bash
npm install
npm test           # 272 unit tests - all rules, scanner, reporter
npm run typecheck  # TypeScript strict check
npm run lint       # ESLint
```

### Reporting issues

Open an issue at [github.com/guptaaayush432/anchor-audit/issues](https://github.com/guptaaayush432/anchor-audit/issues).

---

## License

[MIT](./LICENSE) - Aayush Gupta, 2026
