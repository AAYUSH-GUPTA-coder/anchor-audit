/**
 * Report rendering: markdown (default) or JSON, severity-sorted, written to
 * stdout or `--output`. Sets process exit code 1 when any critical or high
 * finding is present.
 */
import type { CliOptions } from "./index.js";
import type { Finding } from "./auditor.js";

export async function renderReport(
  _findings: Finding[],
  _options: CliOptions
): Promise<void> {
  // TODO(Phase 4): summary table, per-finding sections per PRD §5 output
  // format, JSON schema output, exit-code handling.
  throw new Error("not implemented yet (Phase 4) — see IMPLEMENTATION_PLAN.md");
}
