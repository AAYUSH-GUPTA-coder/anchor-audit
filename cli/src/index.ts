#!/usr/bin/env node
import { Command } from "commander";
import chalk from "chalk";
import { basename } from "node:path";
import { scanProgram } from "./scanner.js";
import { loadRules } from "./rules-loader.js";
import { runAudit } from "./auditor.js";
import { renderReport } from "./reporter.js";
import { buildMetadata } from "./metadata.js";

export type Severity = "critical" | "high" | "medium" | "low";
export type Effort = "low" | "medium" | "high";

export type Provider =
  | "anthropic"
  | "openai"
  | "google"
  | "groq"
  | "openrouter"
  // Local inference backends
  | "ollama"
  | "lmstudio"
  | "vllm"
  // Generic OpenAI-compatible
  | "custom";

/** Default model ID for each provider. */
export const DEFAULT_MODELS: Record<Provider, string> = {
  // Cloud
  anthropic: "claude-sonnet-4-6",
  openai: "gpt-4o",
  google: "gemini-2.0-flash",
  groq: "llama-3.3-70b-versatile",
  openrouter: "anthropic/claude-sonnet-4-6",
  // Local
  ollama: "llama3.1:8b",
  lmstudio: "local-model",
  vllm: "local-model",
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
  effort: Effort;
}

const VALID_PROVIDERS = Object.keys(DEFAULT_MODELS) as Provider[];
const VALID_EFFORTS: Effort[] = ["low", "medium", "high"];

const program = new Command();

program
  .name("anchor-audit")
  .description(
    "Security audit for Anchor programs on Solana.\n" +
      "Cloud: anthropic, openai, google, groq, openrouter\n" +
      "Local: ollama, lmstudio, vllm, custom"
  )
  .argument("<path>", "path to the Anchor program source directory")
  .option("--output <path>", "also write report to this specific file")
  .option("--rules <ids>", "comma-separated rule IDs to run (default: all 50)")
  .option(
    "--severity <min>",
    "minimum severity to report: critical | high | medium | low"
  )
  .option("--format <fmt>", "output format: markdown | json", "markdown")
  .option("--verbose", "print per-rule batch progress", false)
  .option(
    "--api-key <key>",
    "API key (overrides env var; not required for local providers)"
  )
  .option(
    "--provider <name>",
    `AI provider: ${VALID_PROVIDERS.join(" | ")}`,
    "anthropic"
  )
  .option("--model <id>", "model ID (default depends on --provider; see README)")
  .option(
    "--base-url <url>",
    "base URL for OpenAI-compatible endpoint (required for --provider custom; " +
      "optional override for ollama/lmstudio/vllm defaults)"
  )
  .option(
    "--effort <level>",
    "analysis depth — low (2 k tokens) | medium (4 k) | high (8 k)",
    "medium"
  )
  .version("0.1.0")
  .action(async (targetPath: string, opts: Partial<CliOptions>) => {
    const startTime = new Date();
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

    const effort = (opts.effort ?? "medium") as Effort;
    if (!VALID_EFFORTS.includes(effort)) {
      console.error(
        chalk.red(
          `error: --effort must be one of: ${VALID_EFFORTS.join(" | ")}`
        )
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
      effort,
    };

    try {
      const sources = await scanProgram(targetPath);
      const rules = await loadRules(options.rules);
      const findings = await runAudit(sources, rules, options);

      const meta = buildMetadata({
        model: options.model,
        provider: options.provider,
        effort: options.effort,
        project: basename(targetPath),
        startTime,
        totalFiles: sources.length,
        totalFindings: findings.length,
      });

      await renderReport(findings, options, meta);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      console.error(chalk.red(`error: ${message}`));
      process.exit(2);
    }
  });

program.parseAsync(process.argv);
