/**
 * Unit tests for the CLI modules.
 *
 * These tests do NOT call the Claude API; auditor.ts is covered separately
 * by the end-to-end test against the vulnerable-vault example.
 */
import { describe, expect, it } from "vitest";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { existsSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { randomBytes } from "node:crypto";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// scanner
// ---------------------------------------------------------------------------
describe("scanner", () => {
  it("collects .rs files from the fixture directory", async () => {
    const { scanProgram } = await import("../cli/src/scanner.js");
    const files = await scanProgram(join(root, "tests/fixtures"));
    expect(files.length).toBeGreaterThanOrEqual(2);
    for (const f of files) {
      expect(f.path.endsWith(".rs")).toBe(true);
      expect(typeof f.content).toBe("string");
      expect(f.content.length).toBeGreaterThan(0);
    }
  });

  it("rejects a non-existent path", async () => {
    const { scanProgram } = await import("../cli/src/scanner.js");
    await expect(scanProgram("/tmp/does-not-exist-xyz-abc")).rejects.toThrow(
      /does not exist/i
    );
  });

  it("rejects a file instead of a directory", async () => {
    const { scanProgram } = await import("../cli/src/scanner.js");
    await expect(
      scanProgram(join(root, "tests/fixtures/missing_signer.rs"))
    ).rejects.toThrow(/must be a directory/i);
  });

  it("skips target/ and node_modules/ directories", async () => {
    // Create a temp tree with a target/ subdir containing .rs files
    const tmp = join(tmpdir(), `anchor-audit-test-${randomBytes(4).toString("hex")}`);
    mkdirSync(join(tmp, "src"), { recursive: true });
    mkdirSync(join(tmp, "target/build"), { recursive: true });
    writeFileSync(join(tmp, "src/lib.rs"), "fn main() {}");
    writeFileSync(join(tmp, "target/build/artifact.rs"), "// should be skipped");
    try {
      const { scanProgram } = await import("../cli/src/scanner.js");
      const files = await scanProgram(tmp);
      expect(files.every((f) => !f.path.startsWith("target"))).toBe(true);
      expect(files.some((f) => f.path.includes("lib.rs"))).toBe(true);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("collects all .rs files from the vulnerable-vault example", async () => {
    const { scanProgram } = await import("../cli/src/scanner.js");
    const vaultPath = join(
      root,
      "examples/01-vulnerable-vault/programs/vulnerable_vault"
    );
    if (!existsSync(vaultPath)) return; // graceful skip if not present
    const files = await scanProgram(vaultPath);
    expect(files.some((f) => f.path.endsWith("lib.rs"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// rules-loader
// ---------------------------------------------------------------------------
describe("rules-loader", () => {
  it("loads all 50 rules with correct structure", async () => {
    const { loadRules } = await import("../cli/src/rules-loader.js");
    const rules = await loadRules();
    expect(rules.length).toBe(50);
    for (const r of rules) {
      expect(r.id).toMatch(/^\d{3}$/);
      expect(r.name.length).toBeGreaterThan(0);
      expect(["critical", "high", "medium", "low"]).toContain(r.severity);
      expect(r.category.length).toBeGreaterThan(0);
      expect(r.content.length).toBeGreaterThan(100);
    }
  });

  it("filters by comma-separated IDs", async () => {
    const { loadRules } = await import("../cli/src/rules-loader.js");
    const rules = await loadRules("001,017,030");
    expect(rules.length).toBe(3);
    expect(rules.map((r) => r.id).sort()).toEqual(["001", "017", "030"]);
  });

  it("pads single-digit IDs correctly", async () => {
    const { loadRules } = await import("../cli/src/rules-loader.js");
    const rules = await loadRules("1,17");
    expect(rules.map((r) => r.id).sort()).toEqual(["001", "017"]);
  });

  it("throws on an empty result after filtering", async () => {
    const { loadRules } = await import("../cli/src/rules-loader.js");
    await expect(loadRules("999")).rejects.toThrow(/999/);
  });

  it("has rules 001, 017, 030 marked critical", async () => {
    const { loadRules } = await import("../cli/src/rules-loader.js");
    const rules = await loadRules("001,017,030");
    for (const r of rules) {
      expect(r.severity).toBe("critical");
    }
  });
});

// ---------------------------------------------------------------------------
// reporter
// ---------------------------------------------------------------------------
describe("reporter", () => {
  const mockFindings = [
    {
      ruleId: "001",
      ruleName: "missing-signer-check",
      severity: "critical" as const,
      title: "Missing signer check in set_admin",
      file: "programs/vault/src/lib.rs",
      line: 42,
      description: "The authority account is not a Signer.",
      vulnerableCode: "pub authority: AccountInfo<'info>,",
      recommendation: "Use Signer<'info> instead of AccountInfo.",
    },
    {
      ruleId: "025",
      ruleName: "precision-loss",
      severity: "medium" as const,
      title: "Division before multiplication in fee calc",
      file: "programs/vault/src/lib.rs",
      line: 87,
      description: "fee = amount / DENOM * fee_bps rounds to zero.",
      vulnerableCode: "let fee = amount / DENOM * fee_bps as u64;",
      recommendation: "Multiply first: amount * fee_bps as u64 / DENOM",
    },
  ];

  it("renderMarkdown produces the PRD summary table", async () => {
    const { renderMarkdown } = await import("../cli/src/reporter.js");
    const md = renderMarkdown(mockFindings);
    expect(md).toContain("# Anchor Audit Report");
    expect(md).toContain("## Summary");
    expect(md).toContain("## Findings");
    expect(md).toContain("| Critical");
    expect(md).toContain("[CRITICAL]");
    expect(md).toContain("[MEDIUM]");
    expect(md).toContain("Rule 001");
    expect(md).toContain("programs/vault/src/lib.rs:42");
  });

  it("renderMarkdown emits a no-findings message for empty input", async () => {
    const { renderMarkdown } = await import("../cli/src/reporter.js");
    const md = renderMarkdown([]);
    expect(md).toContain("No findings");
    expect(md).not.toContain("## Findings");
  });

  it("renderJson produces valid JSON matching the documented schema", async () => {
    const { renderJson } = await import("../cli/src/reporter.js");
    const json = renderJson(mockFindings);
    const parsed = JSON.parse(json) as {
      version: string;
      date: string;
      summary: { critical: number; high: number; medium: number; low: number; total: number };
      findings: typeof mockFindings;
    };
    expect(parsed.version).toBe("0.1.0");
    expect(parsed.date).toMatch(/^\d{4}-\d{2}-\d{2}$/);
    expect(parsed.summary.critical).toBe(1);
    expect(parsed.summary.medium).toBe(1);
    expect(parsed.summary.total).toBe(2);
    expect(parsed.findings.length).toBe(2);
    expect(parsed.findings[0]?.ruleId).toBe("001");
  });

  it("countBySeverity tallies correctly", async () => {
    const { countBySeverity } = await import("../cli/src/reporter.js");
    const counts = countBySeverity(mockFindings);
    expect(counts.critical).toBe(1);
    expect(counts.high).toBe(0);
    expect(counts.medium).toBe(1);
    expect(counts.low).toBe(0);
  });

  it("findings are sorted critical → high → medium → low in markdown", async () => {
    const { renderMarkdown } = await import("../cli/src/reporter.js");
    const mixed = [
      { ...mockFindings[1]!, severity: "low" as const },
      { ...mockFindings[0]!, severity: "high" as const },
      { ...mockFindings[0]!, severity: "critical" as const },
    ];
    const md = renderMarkdown(mixed);
    const critIdx = md.indexOf("[CRITICAL]");
    const highIdx = md.indexOf("[HIGH]");
    const lowIdx = md.indexOf("[LOW]");
    expect(critIdx).toBeLessThan(highIdx);
    expect(highIdx).toBeLessThan(lowIdx);
  });

  it("SEVERITY_ORDER has correct ordering", async () => {
    const { SEVERITY_ORDER } = await import("../cli/src/reporter.js");
    expect(SEVERITY_ORDER.critical).toBeLessThan(SEVERITY_ORDER.high);
    expect(SEVERITY_ORDER.high).toBeLessThan(SEVERITY_ORDER.medium);
    expect(SEVERITY_ORDER.medium).toBeLessThan(SEVERITY_ORDER.low);
  });
});
