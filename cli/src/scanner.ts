/**
 * File collection for the audit target.
 *
 * Recursively walks the target directory, collects every `.rs` source file,
 * and warns (but does not fail) when the layout doesn't look like an Anchor
 * program (no `lib.rs` found).
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

export interface SourceFile {
  /** Path relative to the audit target root. */
  path: string;
  content: string;
}

const SKIP_DIRS = new Set(["target", "node_modules", ".git", ".anchor"]);

export async function scanProgram(targetPath: string): Promise<SourceFile[]> {
  if (!existsSync(targetPath)) {
    throw new Error(`Target path does not exist: ${targetPath}`);
  }
  if (!statSync(targetPath).isDirectory()) {
    throw new Error(`Target must be a directory: ${targetPath}`);
  }

  const files: SourceFile[] = [];
  collectRs(targetPath, targetPath, files);

  if (files.length === 0) {
    throw new Error(`No .rs source files found under: ${targetPath}`);
  }

  const hasLibRs = files.some((f) => f.path.endsWith("lib.rs"));
  if (!hasLibRs) {
    process.stderr.write(
      `warning: no lib.rs found under ${targetPath} — may not be an Anchor program\n`
    );
  }

  return files;
}

function collectRs(base: string, dir: string, out: SourceFile[]): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      collectRs(base, join(dir, entry.name), out);
    } else if (entry.isFile() && entry.name.endsWith(".rs")) {
      const full = join(dir, entry.name);
      out.push({ path: relative(base, full), content: readFileSync(full, "utf8") });
    }
  }
}
