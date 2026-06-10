/**
 * Loads the rule catalog from the `rules/` directory and parses each rule's
 * ID, title, severity, and category from its markdown.
 *
 * Resolution order (first that exists wins):
 *   1. repo layout  — <dist>/../../rules   (cli/dist/../../rules)
 *   2. npm install  — <dist>/../rules      (dist/../rules)
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { Severity } from "./index.js";

export interface Rule {
  /** Zero-padded three-digit ID, e.g. "001". */
  id: string;
  /** Slug from the filename, e.g. "missing-signer-check". */
  name: string;
  severity: Severity;
  category: string;
  /** Full markdown content — sent to the model as audit context. */
  content: string;
}

function findRulesDir(): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, "..", "..", "rules"), // repo: cli/dist/../../rules
    join(here, "..", "rules"),       // installed: cli/dist/../rules
  ];
  for (const c of candidates) {
    if (existsSync(join(c, "INDEX.md"))) return c;
  }
  throw new Error(
    `Cannot locate rules/ directory. Tried:\n` +
      candidates.map((c) => `  ${c}`).join("\n") +
      `\nRun anchor-audit from the repo root or reinstall the package.`
  );
}

function parseSeverity(content: string, file: string): Severity {
  const m = content.match(/\*\*Severity:\*\*\s*(Critical|High|Medium|Low)/i);
  if (!m?.[1]) throw new Error(`No **Severity:** line found in ${file}`);
  return m[1].toLowerCase() as Severity;
}

function parseCategory(content: string): string {
  const m = content.match(/\*\*Category:\*\*\s*(.+)/);
  return m?.[1]?.trim() ?? "Unknown";
}

export async function loadRules(ruleIdsArg?: string): Promise<Rule[]> {
  const rulesDir = findRulesDir();
  const requested = ruleIdsArg
    ? new Set(ruleIdsArg.split(",").map((s) => s.trim().padStart(3, "0")))
    : null;

  const files = readdirSync(rulesDir)
    .filter((f) => /^\d{3}-.+\.md$/.test(f))
    .sort();

  const rules: Rule[] = [];
  for (const file of files) {
    const id = file.slice(0, 3);
    if (requested && !requested.has(id)) continue;
    const content = readFileSync(join(rulesDir, file), "utf8");
    rules.push({
      id,
      name: file.slice(4, -3), // strip "NNN-" prefix and ".md" suffix
      severity: parseSeverity(content, file),
      category: parseCategory(content),
      content,
    });
  }

  if (rules.length === 0) {
    throw new Error(
      requested
        ? `No rules found for IDs: ${ruleIdsArg}`
        : `No rule files found in ${rulesDir}`
    );
  }
  return rules;
}
