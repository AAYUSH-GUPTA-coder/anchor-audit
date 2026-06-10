import { describe, expect, it } from "vitest";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");

describe("repo scaffolding", () => {
  it("has the PRD-mandated layout", () => {
    for (const path of [
      "SKILL.md",
      "README.md",
      "LICENSE",
      "package.json",
      "tsconfig.json",
      "rules/README.md",
      "rules/INDEX.md",
      "examples/README.md",
      "cli/package.json",
      "cli/src/index.ts",
      "cli/src/scanner.ts",
      "cli/src/auditor.ts",
      "cli/src/reporter.ts",
      "cli/src/rules-loader.ts",
      ".github/workflows/ci.yml",
    ]) {
      expect(existsSync(join(root, path)), `${path} should exist`).toBe(true);
    }
  });

  it("SKILL.md has valid Agent Skills frontmatter", () => {
    const skill = readFileSync(join(root, "SKILL.md"), "utf8");
    expect(skill.startsWith("---\n")).toBe(true);
    expect(skill).toMatch(/^name: anchor-audit$/m);
    expect(skill).toMatch(/^description: .+/m);
  });

  it("cli package exposes the anchor-audit bin", () => {
    const pkg = JSON.parse(
      readFileSync(join(root, "cli/package.json"), "utf8")
    ) as { name: string; bin: Record<string, string> };
    expect(pkg.name).toBe("anchor-audit");
    expect(pkg.bin["anchor-audit"]).toBeDefined();
  });
});
