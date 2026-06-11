#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { scanProgram } from "./scanner.js";
import { loadRules } from "./rules-loader.js";
import { runAudit } from "./auditor.js";
import { renderReport } from "./reporter.js";

export type Severity = "critical" | "high" | "medium" | "low";

export type Provider =
  | "anthropic"
  | "openai"
  | "google"
  | "groq"
  | "openrouter"
  | "custom";

/** Default model ID for each provider. */
export const DEFAULT_MODELS: Record<Provider, string> = {
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-4o",
  google: "gemini-2.0-flash",
  groq: "llama-3.3-70b-versatile",
  openrouter: "anthropic/claude-sonnet-4-6",
  custom: "gpt-4o",
};

export interface CliOptions {
  output?: string;
  rules?: string;
  severity?: Severity;
  format: "markdown" | "json";
  verbose: boolean;
  apiKey?: string;
  model: string;
  provider: Provider;
  baseUrl?: string;
}

const VALID_PROVIDERS = Object.keys(DEFAULT_MODELS) as Provider[];

const program = new Command();

program
  .name("anchor-audit")
  .description(
    "Security audit for Anchor programs on Solana. Supports Anthropic, OpenAI, Google, Groq, OpenRouter, and any OpenAI-compatible endpoint."
  )
  .argument("<path>", "path to the Anchor program source directory")
  .option("--output <path>", "output file (default: stdout)")
  .option("--rules <ids>", "comma-separated rule IDs to run (default: all 50)")
  .option(
    "--severity <min>",
    "minimum severity to report: critical | high | medium | low"
  )
  .option("--format <fmt>", "output format: markdown | json", "markdown")
  .option("--verbose", "print per-rule batch progress", false)
  .option("--api-key <key>", "API key (overrides provider env var)")
  .option(
    "--provider <name>",
    `AI provider: ${VALID_PROVIDERS.join(" | ")}`,
    "anthropic"
  )
  .option(
    "--model <id>",
    "model ID (default depends on --provider; see README)"
  )
  .option(
    "--base-url <url>",
    "base URL for OpenAI-compatible endpoints (use with --provider custom)"
  )
  .version("0.1.0")
  .action(async (targetPath: string, opts: Partial<CliOptions>) => {
    const provider = (opts.provider ?? "anthropic") as Provider;

    if (!VALID_PROVIDERS.includes(provider)) {
      console.error(
        chalk.red(
          `error: unknown provider "${provider}". Valid: ${VALID_PROVIDERS.join(", ")}`
        )
      );
      process.exit(2);
    }

    if (provider === "custom" && !opts.baseUrl) {
      console.error(
        chalk.red(`error: --provider custom requires --base-url <url>`)
      );
      process.exit(2);
    }

    const options: CliOptions = {
      output: opts.output,
      rules: opts.rules,
      severity: opts.severity,
      format: (opts.format ?? "markdown") as "markdown" | "json",
      verbose: opts.verbose ?? false,
      apiKey: opts.apiKey,
      model: opts.model ?? DEFAULT_MODELS[provider],
      provider,
      baseUrl: opts.baseUrl,
    };

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
