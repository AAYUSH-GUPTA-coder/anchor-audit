/**
 * Loads the rule catalog (`/rules/*.md`) from the installed package and
 * parses each rule's ID, title, severity, and category from its markdown.
 */
import type { Severity } from "./index.js";

export interface Rule {
  /** Zero-padded rule ID, e.g. "001". */
  id: string;
  /** Slug from the filename, e.g. "missing-signer-check". */
  name: string;
  severity: Severity;
  category: string;
  /** Full markdown body, sent to the model as audit context. */
  content: string;
}

export async function loadRules(_ruleIds?: string): Promise<Rule[]> {
  // TODO(Phase 4): resolve the rules/ directory relative to the package
  // root, parse frontmatter-ish headers, filter by requested IDs.
  throw new Error("not implemented yet (Phase 4) — see IMPLEMENTATION_PLAN.md");
}
