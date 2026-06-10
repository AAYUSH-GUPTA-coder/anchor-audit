# anchor-audit CLI

AI-driven security audit CLI for Anchor programs on Solana. Sends your program source plus the [rule catalog](../rules) to the Claude API and renders a structured audit report.

> **Status:** scaffolding only — implementation lands in Phase 4 (see [IMPLEMENTATION_PLAN.md](../IMPLEMENTATION_PLAN.md)).

```bash
anchor-audit <path-to-anchor-program> [options]

Options:
  --output <path>    output file (default: stdout)
  --rules <ids>      comma-separated rule IDs (default: all)
  --severity <min>   minimum severity to report (critical | high | medium | low)
  --format <fmt>     markdown (default) | json
  --verbose          print per-rule progress
  --api-key <key>    override ANTHROPIC_API_KEY env var
  --model <id>       override default model (claude-sonnet-4-6)
```

Requires Node 20+ and an `ANTHROPIC_API_KEY`. Exit code is `0` when no critical/high findings, `1` otherwise, `2` on execution error.

## Module layout

- `src/index.ts` — entry point and flag parsing
- `src/scanner.ts` — file collection + filtering
- `src/rules-loader.ts` — loads `/rules/*.md` at runtime
- `src/auditor.ts` — Claude API orchestration (rules batched 4–6 per call)
- `src/reporter.ts` — markdown/JSON report generation
