/**
 * Claude API orchestration.
 *
 * Batches the rule catalog into groups of BATCH_SIZE (5), sends each batch
 * alongside the target source files, and parses structured JSON findings
 * from the response. Aggregates and severity-sorts results across all batches.
 */
import Anthropic from "@anthropic-ai/sdk";
import chalk from "chalk";
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

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

const BATCH_SIZE = 5;

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

function buildSystem(rules: Rule[]): string {
  const blocks = rules
    .map(
      (r) =>
        `### Rule ${r.id}: ${r.name} [${r.severity.toUpperCase()}]\n\n${r.content}`
    )
    .join("\n\n---\n\n");

  return `You are a Solana Anchor smart-contract security auditor.

Analyze the provided Rust source files for violations of the security rules below.
Return ONLY a valid JSON array of findings — no markdown fences, no commentary.
If you find no violations, return exactly: []

Each object in the array must match this schema:
{
  "ruleId":         "<NNN>",          // three-digit string, e.g. "017"
  "severity":       "<level>",        // one of: critical | high | medium | low
  "title":          "<string>",       // ≤ 100 chars; what was found
  "file":           "<path>",         // as given in the <file path="..."> tag
  "line":           <number | null>,  // best-effort integer line number
  "description":    "<string>",       // what the code does wrong and why it matters
  "vulnerableCode": "<string>",       // relevant snippet, ≤ 400 chars
  "recommendation": "<string>"        // concrete, actionable fix
}

Security rules to check:

${blocks}`;
}

function buildUser(sources: SourceFile[]): string {
  return sources
    .map((s) => `<file path="${s.path}">\n${s.content}\n</file>`)
    .join("\n\n");
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

function parseFindings(raw: string, rules: Rule[]): Finding[] {
  const cleaned = raw
    .replace(/^```(?:json)?\r?\n?/m, "")
    .replace(/\r?\n?```$/m, "")
    .trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  const ruleMap = new Map(rules.map((r) => [r.id, r]));
  const findings: Finding[] = [];

  for (const item of parsed) {
    if (typeof item !== "object" || item === null) continue;
    const obj = item as Record<string, unknown>;

    const rawId = String(obj["ruleId"] ?? "");
    const id = rawId.padStart(3, "0");
    const rule = ruleMap.get(id);
    if (!rule) continue;

    const sev = String(obj["severity"] ?? "").toLowerCase();
    if (!["critical", "high", "medium", "low"].includes(sev)) continue;

    findings.push({
      ruleId: id,
      ruleName: rule.name,
      severity: sev as Severity,
      title: String(obj["title"] ?? "").slice(0, 200),
      file: String(obj["file"] ?? ""),
      line:
        typeof obj["line"] === "number" ? Math.max(1, Math.floor(obj["line"])) : null,
      description: String(obj["description"] ?? ""),
      vulnerableCode: String(obj["vulnerableCode"] ?? "").slice(0, 800),
      recommendation: String(obj["recommendation"] ?? ""),
    });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export async function runAudit(
  sources: SourceFile[],
  rules: Rule[],
  options: CliOptions
): Promise<Finding[]> {
  const apiKey = options.apiKey ?? process.env["ANTHROPIC_API_KEY"];
  if (!apiKey) {
    throw new Error(
      "No API key found. Set the ANTHROPIC_API_KEY environment variable or pass --api-key."
    );
  }

  const client = new Anthropic({ apiKey });

  // When --severity is set, skip rules below that threshold entirely.
  const minOrder = options.severity ? SEVERITY_ORDER[options.severity] : 3;
  const eligible = rules.filter((r) => SEVERITY_ORDER[r.severity] <= minOrder);
  if (eligible.length === 0) return [];

  // Slice into batches of BATCH_SIZE.
  const batches: Rule[][] = [];
  for (let i = 0; i < eligible.length; i += BATCH_SIZE) {
    batches.push(eligible.slice(i, i + BATCH_SIZE));
  }

  const userContent = buildUser(sources);
  const allFindings: Finding[] = [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]!;

    if (options.verbose) {
      process.stderr.write(
        chalk.dim(
          `  [${i + 1}/${batches.length}] rules ${batch.map((r) => r.id).join(", ")}\n`
        )
      );
    }

    let msg: Anthropic.Message;
    try {
      msg = await client.messages.create({
        model: options.model,
        max_tokens: 4096,
        system: buildSystem(batch),
        messages: [{ role: "user", content: userContent }],
      });
    } catch (err) {
      const text = err instanceof Error ? err.message : String(err);
      throw new Error(`Claude API error on batch ${i + 1}: ${text}`);
    }

    const responseText =
      msg.content[0]?.type === "text" ? msg.content[0].text : "";
    const batchFindings = parseFindings(responseText, batch);

    if (options.verbose && batchFindings.length > 0) {
      process.stderr.write(
        chalk.yellow(`    → ${batchFindings.length} finding(s)\n`)
      );
    }

    allFindings.push(...batchFindings);
  }

  // Apply severity filter to findings as well (model may downgrade severity).
  const filtered = allFindings.filter(
    (f) => SEVERITY_ORDER[f.severity] <= minOrder
  );

  // Sort critical → low, stable within each tier.
  return filtered.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
}
