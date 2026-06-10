/**
 * File collection and filtering for the audit target.
 *
 * Validates that the target path contains an Anchor program layout
 * (`programs/<name>/src/lib.rs` or loose `.rs` files) and collects all
 * Rust sources, annotated with their file paths.
 */

export interface SourceFile {
  /** Path relative to the audit target root. */
  path: string;
  content: string;
}

export async function scanProgram(_targetPath: string): Promise<SourceFile[]> {
  // TODO(Phase 4): validate Anchor layout, walk the tree, filter .rs files.
  throw new Error("not implemented yet (Phase 4) — see IMPLEMENTATION_PLAN.md");
}
