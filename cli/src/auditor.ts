/**
 * Claude API orchestration.
 *
 * Batches rules in groups of 4–6, sends each batch with the target sources
 * to the Claude API, and parses structured JSON findings from the response.
 */
import type { CliOptions, Severity } from "./index.js";
import type { Rule } from "./rules-loader.js";
import type { SourceFile } from "./scanner.js";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  file: string;
  line: number | null;
  description: string;
  vulnerableCode: string;
  recommendation: string;
}

export async function runAudit(
  _sources: SourceFile[],
  _rules: Rule[],
  _options: CliOptions
): Promise<Finding[]> {
  // TODO(Phase 4): batch rules, call the Claude API (@anthropic-ai/sdk),
  // request structured JSON output, aggregate findings across batches.
  throw new Error("not implemented yet (Phase 4) — see IMPLEMENTATION_PLAN.md");
}
