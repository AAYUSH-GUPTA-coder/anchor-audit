import { describe, expect, it } from "vitest";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const rulesDir = join(root, "rules");

const ruleFiles = readdirSync(rulesDir)
  .filter((f) => /^\d{3}-.+\.md$/.test(f))
  .sort();

const REQUIRED_SECTIONS = [
  "## Description",
  "## Vulnerable pattern",
  "## Why this is dangerous",
  "## Fix pattern",
  "## Detection heuristic",
  "## References",
  "## Real-world exploits",
];

describe("rule catalog", () => {
  it("contains exactly 50 rules numbered 001-050", () => {
    expect(ruleFiles.length).toBe(50);
    ruleFiles.forEach((file, i) => {
      const expected = String(i + 1).padStart(3, "0");
      expect(file.startsWith(`${expected}-`), `${file} should start with ${expected}-`).toBe(true);
    });
  });

  describe.each(ruleFiles)("%s", (file) => {
    const content = readFileSync(join(rulesDir, file), "utf8");
    const id = file.slice(0, 3);

    it("has the correct H1 title with its ID", () => {
      expect(content).toMatch(new RegExp(`^# Rule ${id}: .+`, "m"));
    });

    it("declares a valid severity and category", () => {
      expect(content).toMatch(/^\*\*Severity:\*\* (Critical|High|Medium|Low)/m);
      expect(content).toMatch(/^\*\*Category:\*\* .+/m);
    });

    it("has all seven template sections", () => {
      for (const section of REQUIRED_SECTIONS) {
        expect(content.includes(section), `${file} missing "${section}"`).toBe(true);
      }
    });

    it("cites at least two references with URLs", () => {
      const refs = content.slice(content.indexOf("## References"));
      const urls = refs.match(/https?:\/\/\S+/g) ?? [];
      expect(urls.length, `${file} should cite >=2 sources`).toBeGreaterThanOrEqual(2);
    });

    it("includes a Rust code block", () => {
      expect(content).toMatch(/```rust/);
    });
  });

  it("INDEX.md lists every rule file", () => {
    const index = readFileSync(join(rulesDir, "INDEX.md"), "utf8");
    for (const file of ruleFiles) {
      expect(index.includes(`(./${file})`), `INDEX.md missing link to ${file}`).toBe(true);
    }
  });

  it("SKILL.md stays under 600 lines and links every rule", () => {
    const skill = readFileSync(join(root, "SKILL.md"), "utf8");
    expect(skill.split("\n").length).toBeLessThan(600);
    for (const file of ruleFiles) {
      expect(skill.includes(`rules/${file}`), `SKILL.md missing link to ${file}`).toBe(true);
    }
  });
});
