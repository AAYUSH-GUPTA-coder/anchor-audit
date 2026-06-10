#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { scanProgram } from "./scanner.js";
import { loadRules } from "./rules-loader.js";
import { runAudit } from "./auditor.js";
import { renderReport } from "./reporter.js";

export const DEFAULT_MODEL = "claude-sonnet-4-6";

export type Severity = "critical" | "high" | "medium" | "low";

export interface CliOptions {
  output?: string;
  rules?: string;
  severity?: Severity;
  format: "markdown" | "json";
  verbose: boolean;
  apiKey?: string;
  model: string;
}

const program = new Command();

program
  .name("anchor-audit")
  .description(
    "Security audit for Anchor programs on Solana, driven by the Claude API"
  )
  .argument("<path>", "path to the Anchor program source directory")
  .option("--output <path>", "output file (default: stdout)")
  .option("--rules <ids>", "comma-separated rule IDs (default: all)")
  .option(
    "--severity <min>",
    "minimum severity to report (critical | high | medium | low)"
  )
  .option("--format <fmt>", "output format: markdown | json", "markdown")
  .option("--verbose", "print per-rule progress", false)
  .option("--api-key <key>", "override ANTHROPIC_API_KEY env var")
  .option("--model <id>", "override default model", DEFAULT_MODEL)
  .version("0.1.0")
  .action(async (targetPath: string, options: CliOptions) => {
    try {
      const sources = await scanProgram(targetPath);
      const rules = await loadRules(options.rules);
      const findings = await runAudit(sources, rules, options);
      await renderReport(findings, options);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`error: ${message}`));
      process.exit(2);
    }
  });

program.parseAsync(process.argv);
