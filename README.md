# anchor-audit

> **Status: pre-release scaffolding.** Built per [PRD.md](./PRD.md); progress tracked in [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md).

`anchor-audit` is a security audit toolkit for [Anchor](https://www.anchor-lang.com/) programs on Solana, designed to be driven by AI coding agents. It ships a Claude Code **skill** that teaches an agent the Anchor security checklist, and a **CLI** that runs the same 50-rule catalog against a program directory via the Claude API and produces a structured markdown audit report. Both share one rule catalog in [`/rules`](./rules), so updates propagate to both.

## Install — Claude Code skill

<!-- TODO(Phase 6): SendAI skill install command. -->

Manual fallback:

```bash
git clone https://github.com/<owner>/anchor-audit
cp -r anchor-audit ~/.claude/skills/anchor-audit
```

## Install — CLI

```bash
npm install -g anchor-audit
export ANTHROPIC_API_KEY=sk-ant-...
```

## Usage

Skill mode (inside Claude Code):

```
> audit my anchor program in ./programs/my-vault
```

CLI mode:

```bash
anchor-audit ./programs/my-vault
anchor-audit ./programs/my-vault --output ./AUDIT.md
anchor-audit ./programs/my-vault --rules 001,005,009 --verbose
anchor-audit ./programs/my-vault --severity high --format json
```

## Rule catalog

<!-- TODO(Phase 2): full 50-row table — ID | Rule | Severity | Category —
     with each row linking to its file in /rules/. -->

50 rules across 8 categories: account validation, PDA safety, CPI safety, math and value handling, authorization and lifecycle, Anchor constraint hygiene, SPL token specifics, and SVM/runtime. See [rules/INDEX.md](./rules/INDEX.md).

## Limitations

This tool is a **first-pass triage aid**, not a replacement for a human security audit. It performs static, pattern-based review driven by an LLM: it can miss vulnerabilities (especially business-logic flaws) and can report false positives. Do not deploy to mainnet on the strength of a clean `anchor-audit` report alone — get a professional audit.

## Contributing

<!-- TODO(Phase 6): contribution guide — rule template, how to add a rule,
     how to run tests. -->

Rules live in [`/rules`](./rules) and follow the template in [rules/README.md](./rules/README.md). PRs welcome.

## License

[MIT](./LICENSE)
