# anchor-audit, Product Requirements Document

## 1. Project overview

`anchor-audit` is a security audit toolkit for Anchor programs on Solana, designed to be driven by AI coding agents (Claude Code, Cursor, Codex). It ships two artifacts:

1. **A Claude Code skill** (`SKILL.md`) that teaches an AI agent the Anchor security checklist with concrete vulnerable-code patterns and fix patterns
2. **A CLI tool** (`anchor-audit`) that accepts an Anchor program source directory, runs the skill against it via the Claude API, and outputs a structured markdown audit report

Both artifacts share the same underlying rule catalog (`/rules/`), so updates to the rules propagate to both.

---

## 2. Repository structure

Build the repo exactly to this layout:

```
anchor-audit/
├── SKILL.md
├── README.md
├── LICENSE                      (MIT)
├── package.json
├── tsconfig.json
├── rules/
│   ├── README.md
│   ├── 001-missing-signer-check.md
│   ├── 002-missing-owner-check.md
│   ├── 003-missing-discriminator-check.md
│   ├── ... (one file per rule)
│   └── INDEX.md                 (table of all rules with severity)
├── examples/
│   ├── README.md
│   ├── 01-vulnerable-vault/     (intentionally buggy reference program)
│   │   ├── programs/
│   │   ├── README.md
│   │   └── EXPECTED_FINDINGS.md
│   ├── 02-real-program-audit/   (audit of a real OSS Anchor program)
│   │   └── AUDIT_REPORT.md
│   └── 03-real-program-audit/   (audit of a second OSS Anchor program)
│       └── AUDIT_REPORT.md
├── cli/
│   ├── src/
│   │   ├── index.ts             (entry point)
│   │   ├── scanner.ts           (file collection + filtering)
│   │   ├── auditor.ts           (Claude API orchestration)
│   │   ├── reporter.ts          (markdown report generation)
│   │   └── rules-loader.ts      (loads /rules/*.md at runtime)
│   ├── package.json
│   └── README.md
├── tests/
│   └── fixtures/                (small Anchor snippets for unit tests)
└── .github/
    └── workflows/
        └── ci.yml               (lint + typecheck + test on PR)
```

---

## 3. The SKILL.md

Author per the Anthropic Agent Skills specification. The skill is invoked by Claude Code when a user asks to audit, review, or check Anchor / Solana program code.

### Frontmatter

```yaml
---
name: anchor-audit
description: Audits Anchor programs on Solana for security vulnerabilities. Use this skill when reviewing, auditing, or checking Solana smart contract code written with the Anchor framework. Covers signer checks, account validation, CPI safety, PDA seeds, lamport arithmetic, SPL token handling, and Anchor-specific constraint vulnerabilities.
---
```

### Body sections

1. **When to invoke** (one paragraph telling Claude exactly when this skill applies)
2. **Audit workflow** (step-by-step instructions: discover entry points → enumerate accounts → run rule catalog → produce findings)
3. **Rule catalog** (one bullet per rule with a link to `/rules/NNN-name.md`)
4. **Output format** (Severity levels, finding template, summary table)
5. **Limitations** (what the skill does and does not catch; recommend manual review for production)

Keep `SKILL.md` itself under 600 lines. The detailed rule content lives in `/rules/` files that the skill links to, so Claude pulls them in only when relevant.

---

## 4. Rule catalog (v1, 50 rules)

Ship exactly these 50 rules in v1. Each is one file in `/rules/` with the structure defined in Section 4.2 below.

### 4.1 The rules

#### Account validation (10)
1. **001-missing-signer-check** Instructions that should require a signer but don't enforce it
2. **002-missing-owner-check** Account passed in without verifying the program that owns it
3. **003-missing-discriminator-check** Account type confusion via missing 8-byte Anchor discriminator
4. **004-account-substitution** Wrong account passed; constraint missing to enforce identity
5. **005-sysvar-spoofing** Sysvar account (Clock, Rent, etc.) passed unchecked
6. **006-missing-rent-exemption-check** Account written to without verifying rent exemption
7. **007-account-aliasing** Same account passed twice for two distinct logical roles
8. **008-uninitialized-account-use** Account read or written before initialization completes
9. **009-missing-mut-constraint** Account modified without `mut` constraint
10. **010-missing-close-constraint** Account close path missing or improperly enforced

#### PDA safety (6)
11. **011-pda-seed-collision** Two PDAs derivable to the same address from different intents
12. **012-missing-bump-validation** Bump used without `bump = ...` constraint or canonical check
13. **013-non-canonical-bump-accepted** Any valid bump accepted instead of the canonical one
14. **014-predictable-pda** PDA derived from attacker-controlled seeds without authorization
15. **015-insecure-pda-across-upgrades** PDA layout changes break account compatibility on upgrade
16. **016-bump-mismatch** Stored bump differs from recomputed bump

#### CPI safety (6)
17. **017-arbitrary-cpi** CPI target program ID not validated against an expected ID
18. **018-cpi-confused-deputy** Privileged action via CPI without checking caller authorization
19. **019-missing-program-id-check-spl** Token / SPL CPIs without explicit program ID verification
20. **020-reentrancy-via-cpi** Cross-program call into untrusted code mid-state-mutation
21. **021-untrusted-callback** External program executed as a callback without validation
22. **022-cpi-with-attacker-accounts** CPI invoked with caller-controlled accounts as arguments

#### Math and value handling (7)
23. **023-lamport-overflow** Lamport arithmetic without `checked_add` / `checked_sub`
24. **024-token-amount-overflow** Token amount arithmetic without checked operations
25. **025-precision-loss** Division before multiplication
26. **026-rounding-direction** Rounding favors user over protocol
27. **027-token-decimal-mismatch** Operations on token amounts across mints with different decimals
28. **028-integer-cast-truncation** `as u64`, `as u32` casts losing high bits
29. **029-off-by-one** Iteration or indexing off-by-one errors

#### Authorization and lifecycle (8)
30. **030-missing-authorization** Privileged instruction (close, withdraw, admin) without signer or `has_one`
31. **031-reinitialization-attack** Account `init` reachable twice; missing single-init guard
32. **032-closed-account-revival** Closed account reused without close + reallocation guards
33. **033-init-if-needed-misuse** `init_if_needed` allows attacker-controlled initialization paths
34. **034-missing-has-one** Cross-account ownership relationship not enforced via `has_one`
35. **035-insecure-admin-transfer** Admin role transfer in a single step without acceptance handshake
36. **036-missing-pause-guards** Critical instructions have no pause / freeze mechanism
37. **037-clock-manipulation** Time-based logic uses Clock sysvar without bounds or staleness checks

#### Anchor constraint hygiene (6)
38. **038-missing-address-validation** `address = ...` constraint missing on hardcoded-identity accounts
39. **039-constraint-evaluation-stage** Constraint expression evaluated against pre- vs post-state incorrectly
40. **040-realloc-zero-init** `realloc` without zero-init flag exposes leftover memory
41. **041-missing-payer-on-init** `init` constraint without `payer` defined
42. **042-incorrect-space-allocation** `space` value too small for the account struct
43. **043-account-vs-account-info** `Account<'info, T>` vs `AccountInfo<'info>` misuse weakens validation

#### SPL token specifics (4)
44. **044-token-account-owner-unverified** Token account passed without owner verification
45. **045-token-mint-unverified** Token account passed without mint verification
46. **046-ata-assumption-errors** Code assumes associated token account exists or is correctly derived
47. **047-token-program-id-hardcoded** Token program ID hardcoded vs. passed and validated

#### SVM / runtime (3)
48. **048-compute-budget-abuse** Unbounded loops or recursion causing compute exhaustion DoS
49. **049-log-spam-dos** Attacker-controlled logging causes excessive log emission
50. **050-stack-overflow-deep-cpi** Stack frame exhaustion via deeply nested CPI chains

### 4.2 Rule file template

Every `/rules/NNN-name.md` must follow this exact structure:

```markdown
# Rule NNN: <Title>

**Severity:** Critical | High | Medium | Low
**Category:** Account validation | PDA | CPI | Math | Auth | Constraints | SPL Token | Runtime

## Description
One paragraph explaining the vulnerability and why it matters.

## Vulnerable pattern
\`\`\`rust
// Minimal Rust/Anchor snippet showing the bug
\`\`\`

## Why this is dangerous
Explain attacker action and impact in 2 to 4 sentences.

## Fix pattern
\`\`\`rust
// Minimal Rust/Anchor snippet showing the corrected code
\`\`\`

## Detection heuristic
Bullet list of things an agent should look for in source code to flag this rule.

## References
- Source 1 (URL)
- Source 2 (URL)

## Real-world exploits (if any)
Optional: brief mention of public exploits matching this pattern.
```

### 4.3 Source material

When drafting rule content, pull from these sources. Do not invent. Cite where each rule's content came from in the References section of each rule file.

- Neodyme blog: `https://neodyme.io/en/blog/solana_common_pitfalls/`
- Sec3 documentation and audit reports (public)
- Helius security blog
- Solana Cookbook security section
- Cyfrin Updraft Solana security course materials
- Official Anchor book security chapter
- Public audit reports from OtterSec, Halborn, Sec3 on Solana programs

---

## 5. CLI tool spec

### Command

```bash
anchor-audit <path-to-anchor-program>
anchor-audit ./programs/my-vault --output ./AUDIT.md
anchor-audit ./programs/my-vault --rules 001,005,009 --verbose
```

### Flags

- `--output <path>` Output file (default: stdout)
- `--rules <ids>` Comma-separated rule IDs (default: all)
- `--severity <min>` Minimum severity to report (critical | high | medium | low)
- `--format <fmt>` `markdown` (default) | `json`
- `--verbose` Print per-rule progress
- `--api-key <key>` Override `ANTHROPIC_API_KEY` env var
- `--model <id>` Override default model

### Stack

- Node 20+
- TypeScript
- `@anthropic-ai/sdk` for Claude API calls
- `commander` for CLI parsing
- `chalk` for colored output
- Default model: Claude Sonnet 4.6 (`claude-sonnet-4-6`)

### Execution flow

1. Validate arguments. Confirm target path contains `programs/*/src/lib.rs` or `*.rs` files
2. Load `/rules/*.md` from the installed package
3. Read all `.rs` files under the target path, concatenate with file path comments
4. For each rule (or batched groups of 4 to 6 rules to manage context length), send a Claude API call with: the rule content as system context, the source files as user content, and a structured output prompt asking for findings in JSON
5. Aggregate findings across rules
6. Render to markdown with severity sorting, file paths, line numbers, and fix snippets
7. Exit code: 0 if no critical/high, 1 if any critical/high finding

### Output format (markdown report)

```markdown
# Audit Report: <program name>
Generated by anchor-audit vX.X.X on <date>

## Summary
| Severity | Count |
|----------|-------|
| Critical | N     |
| High     | N     |
| Medium   | N     |
| Low      | N     |

## Findings

### [CRITICAL] Rule 017: Arbitrary CPI in `transfer_tokens`
**File:** `programs/my-vault/src/lib.rs:142`

**Description:** ...
**Vulnerable code:** \`\`\`rust ... \`\`\`
**Recommendation:** ...
**Reference:** [Rule 017](https://github.com/.../rules/017-arbitrary-cpi.md)

### [HIGH] Rule 001: Missing signer check ...
...
```

---

## 6. Example programs (`/examples/`)

### Example 1: `01-vulnerable-vault`

Write a small, intentionally buggy Anchor vault program (~300 to 400 lines) that triggers at least 15 of the 50 rules across diverse categories. Include `EXPECTED_FINDINGS.md` listing which rules should fire and where. This serves as the regression test for the CLI and the demo target for the launch recording.

### Examples 2 and 3: `02-real-program-audit` and `03-real-program-audit`

Pick two real, open-source, non-trivial Anchor programs from public GitHub (suggested: small DeFi or utility programs with permissive licenses). Run `anchor-audit` against each. Save the actual report as `AUDIT_REPORT.md`. Do not file PRs against those repos; this is a documentation artifact.

---

## 7. README.md (user-facing)

Must include:

1. One-paragraph project description
2. Install for Claude Code (SendAI skill install command, plus a manual install fallback)
3. Install for CLI (`npm install -g anchor-audit`)
4. Quick usage examples (both skill mode and CLI mode)
5. Rule catalog table (50 rows, with severity column and source links to `/rules/`)
6. Limitations and disclaimer (first-pass triage, not a replacement for human audit)
7. Contributing section
8. License

---

## 8. Acceptance criteria

The build is complete when:

- [ ] `SKILL.md` parses against the Anthropic Agent Skills spec
- [ ] All 50 rules exist as files in `/rules/` and follow the template
- [ ] `/rules/INDEX.md` lists all 50 rules in a table
- [ ] CLI installs globally via `npm install -g .` and runs end-to-end on the vulnerable-vault example, producing a markdown report with all expected findings
- [ ] CLI passes JSON output validation against a documented schema
- [ ] Both real-world example audits exist and were produced by the tool itself
- [ ] README covers install, usage, and limitations, with a complete 50-row rule table
- [ ] CI workflow passes (typecheck, lint)
- [ ] Repo is MIT-licensed, public, with a clean commit history

---

## 9. Explicitly out of scope (v1)

- Pinocchio (non-Anchor) native program support
- Dynamic analysis or fuzzing
- `surfpool` integration for live execution checks
- IDE extensions (VS Code, Cursor inline)
- Web UI or hosted version
- Auto-fix / patch generation
- Custom rule authoring SDK for third parties
- Telemetry, install tracking, or analytics

These are tracked as stretch goals in a separate `ROADMAP.md` but do not block v1 release.

---

## 10. Build plan (suggested phases)

**Phase 1, scaffolding (Day 1):** Create the repo structure, `package.json`, `tsconfig.json`, README skeleton, LICENSE, CI workflow, and `SKILL.md` skeleton with frontmatter and placeholder sections.

**Phase 2, rule catalog (Days 2 to 4):** Draft all 50 rule files using the template. Pull source content from Neodyme, Sec3, Helius, Cyfrin Updraft, and public audit reports. Cite every rule. Build `/rules/INDEX.md` and the `SKILL.md` rule references. Work in batches of ~10 rules per session and review each batch before moving on.

**Phase 3, vulnerable example (Day 5):** Write `01-vulnerable-vault` and its `EXPECTED_FINDINGS.md` covering at least 15 distinct rules.

**Phase 4, CLI (Days 6 to 7):** Implement the CLI per spec. Validate against the vulnerable example. Iterate on prompt engineering until findings match `EXPECTED_FINDINGS.md`.

**Phase 5, real-world audits (Day 8):** Pick two OSS Anchor programs, run the tool, save reports.

**Phase 6, polish (Day 9):** README pass, recording a demo Loom, final cleanup, public release.

Total: ~9 working days. Phases 2 and 4 are AI-heavy and can compress significantly with parallel Claude Code sessions.
