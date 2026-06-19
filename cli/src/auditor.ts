/**
 * AI API orchestration — provider-agnostic.
 *
 * Anthropic is called natively via @anthropic-ai/sdk (best quality).
 * Every other provider (cloud and local) uses the OpenAI-compatible chat
 * completions API via the `openai` package with a custom baseURL.
 *
 * Cloud routing:
 *   anthropic   → @anthropic-ai/sdk   → api.anthropic.com
 *   openai      → openai SDK          → api.openai.com/v1
 *   google      → openai SDK          → generativelanguage.googleapis.com/v1beta/openai/
 *   groq        → openai SDK          → api.groq.com/openai/v1
 *   openrouter  → openai SDK          → openrouter.ai/api/v1
 *
 * Local routing (no API key required):
 *   ollama      → openai SDK          → http://localhost:11434/v1
 *   lmstudio    → openai SDK          → http://localhost:1234/v1
 *   vllm        → openai SDK          → http://localhost:8000/v1
 *   custom      → openai SDK          → <--base-url>
 */
import Anthropic from "@anthropic-ai/sdk";
import OpenAI from "openai";
import chalk from "chalk";
import type { CliOptions, Effort, Provider, Severity } from "./index.js";
import type { Rule } from "./rules-loader.js";
import type { SourceFile } from "./scanner.js";

export interface Finding {
  ruleId: string;
  ruleName: string;
  severity: Severity;
  title: string;
  file: string;
  line: number | null;
  description: string;
  vulnerableCode: string;
  recommendation: string;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};

/** Max tokens per provider call, controlled by --effort. */
const EFFORT_MAX_TOKENS: Record<Effort, number> = {
  low: 2048,
  medium: 4096,
  high: 8192,
};

const BATCH_SIZE = 5;

// ---------------------------------------------------------------------------
// Provider config
// ---------------------------------------------------------------------------

/** Base URLs for OpenAI-compatible providers (cloud and local). */
const PROVIDER_BASE_URLS: Partial<Record<Provider, string>> = {
  // Cloud
  openai: "https://api.openai.com/v1",
  google: "https://generativelanguage.googleapis.com/v1beta/openai/",
  groq: "https://api.groq.com/openai/v1",
  openrouter: "https://openrouter.ai/api/v1",
  // Local — override with --base-url if your server runs on a different port
  ollama: "http://localhost:11434/v1",
  lmstudio: "http://localhost:1234/v1",
  vllm: "http://localhost:8000/v1",
};

/** Environment variable names per cloud provider. */
const PROVIDER_ENV_VARS: Partial<Record<Provider, string>> = {
  anthropic: "ANTHROPIC_API_KEY",
  openai: "OPENAI_API_KEY",
  google: "GEMINI_API_KEY",
  groq: "GROQ_API_KEY",
  openrouter: "OPENROUTER_API_KEY",
  custom: "OPENAI_API_KEY",
};

/** Local providers don't use real API keys; the OpenAI SDK still requires a non-empty string. */
const LOCAL_PROVIDERS = new Set<Provider>(["ollama", "lmstudio", "vllm"]);
const LOCAL_KEY_PLACEHOLDER = "local";

function resolveApiKey(options: CliOptions): string {
  if (options.apiKey) return options.apiKey;

  const envVar = PROVIDER_ENV_VARS[options.provider];
  if (envVar) {
    const key = process.env[envVar];
    if (key) return key;
  }

  // Local providers work without a real API key.
  if (LOCAL_PROVIDERS.has(options.provider)) {
    return LOCAL_KEY_PLACEHOLDER;
  }

  throw new Error(
    `No API key found for provider "${options.provider}".\n` +
      `Set the ${PROVIDER_ENV_VARS[options.provider] ?? "OPENAI_API_KEY"} environment variable or pass --api-key.`
  );
}

// ---------------------------------------------------------------------------
// Prompt builders
// ---------------------------------------------------------------------------

function buildSystem(rules: Rule[]): string {
  const blocks = rules
    .map(
      (r) =>
        `### Rule ${r.id}: ${r.name} [${r.severity.toUpperCase()}]\n\n${r.content}`
    )
    .join("\n\n---\n\n");

  return `You are a Solana Anchor smart-contract security auditor.

Analyze the provided Rust source files for violations of the security rules below.
Return ONLY a valid JSON array of findings — no markdown fences, no commentary.
If you find no violations, return exactly: []

Each object in the array must match this schema:
{
  "ruleId":         "<NNN>",          // three-digit string, e.g. "017"
  "severity":       "<level>",        // one of: critical | high | medium | low
  "title":          "<string>",       // ≤ 100 chars; what was found
  "file":           "<path>",         // as given in the <file path="..."> tag
  "line":           <number | null>,  // best-effort integer line number
  "description":    "<string>",       // what the code does wrong and why it matters
  "vulnerableCode": "<string>",       // relevant snippet, ≤ 400 chars
  "recommendation": "<string>"        // concrete, actionable fix
}

Security rules to check:

${blocks}`;
}

function buildUser(sources: SourceFile[]): string {
  return sources
    .map((s) => `<file path="${s.path}">\n${s.content}\n</file>`)
    .join("\n\n");
}

// ---------------------------------------------------------------------------
// Provider-specific API calls
// ---------------------------------------------------------------------------

async function callAnthropic(
  apiKey: string,
  model: string,
  maxTokens: number,
  system: string,
  user: string
): Promise<string> {
  const client = new Anthropic({ apiKey });
  const msg = await client.messages.create({
    model,
    max_tokens: maxTokens,
    system,
    messages: [{ role: "user", content: user }],
  });
  return msg.content[0]?.type === "text" ? msg.content[0].text : "";
}

async function callOpenAICompatible(
  apiKey: string,
  model: string,
  baseURL: string,
  maxTokens: number,
  system: string,
  user: string
): Promise<string> {
  const client = new OpenAI({ apiKey, baseURL });
  const response = await client.chat.completions.create({
    model,
    max_tokens: maxTokens,
    messages: [
      { role: "system", content: system },
      { role: "user", content: user },
    ],
  });
  return response.choices[0]?.message?.content ?? "";
}

async function callProvider(
  options: CliOptions,
  apiKey: string,
  system: string,
  user: string
): Promise<string> {
  const maxTokens = EFFORT_MAX_TOKENS[options.effort];

  if (options.provider === "anthropic") {
    return callAnthropic(apiKey, options.model, maxTokens, system, user);
  }

  const baseURL =
    options.baseUrl ??
    PROVIDER_BASE_URLS[options.provider] ??
    "https://api.openai.com/v1";

  return callOpenAICompatible(apiKey, options.model, baseURL, maxTokens, system, user);
}

// ---------------------------------------------------------------------------
// Response parsing
// ---------------------------------------------------------------------------

function parseFindings(raw: string, rules: Rule[]): Finding[] {
  const cleaned = raw
    .replace(/^```(?:json)?\r?\n?/m, "")
    .replace(/\r?\n?```$/m, "")
    .trim();

  let parsed: unknown;
  try {
    parsed = JSON.parse(cleaned);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];

  const ruleMap = new Map(rules.map((r) => [r.id, r]));
  const findings: Finding[] = [];

  for (const item of parsed) {
    if (typeof item !== "object" || item === null) continue;
    const obj = item as Record<string, unknown>;

    const id = String(obj["ruleId"] ?? "").padStart(3, "0");
    const rule = ruleMap.get(id);
    if (!rule) continue;

    const sev = String(obj["severity"] ?? "").toLowerCase();
    if (!["critical", "high", "medium", "low"].includes(sev)) continue;

    findings.push({
      ruleId: id,
      ruleName: rule.name,
      severity: sev as Severity,
      title: String(obj["title"] ?? "").slice(0, 200),
      file: String(obj["file"] ?? ""),
      line:
        typeof obj["line"] === "number"
          ? Math.max(1, Math.floor(obj["line"]))
          : null,
      description: String(obj["description"] ?? ""),
      vulnerableCode: String(obj["vulnerableCode"] ?? "").slice(0, 800),
      recommendation: String(obj["recommendation"] ?? ""),
    });
  }
  return findings;
}

// ---------------------------------------------------------------------------
// Main entry
// ---------------------------------------------------------------------------

export async function runAudit(
  sources: SourceFile[],
  rules: Rule[],
  options: CliOptions
): Promise<Finding[]> {
  const apiKey = resolveApiKey(options);

  const minOrder = options.severity ? SEVERITY_ORDER[options.severity] : 3;
  const eligible = rules.filter((r) => SEVERITY_ORDER[r.severity] <= minOrder);
  if (eligible.length === 0) return [];

  const batches: Rule[][] = [];
  for (let i = 0; i < eligible.length; i += BATCH_SIZE) {
    batches.push(eligible.slice(i, i + BATCH_SIZE));
  }

  if (options.verbose) {
    process.stderr.write(
      chalk.dim(
        `provider: ${options.provider}  model: ${options.model}  effort: ${options.effort}  batches: ${batches.length}\n`
      )
    );
  }

  const userContent = buildUser(sources);
  const allFindings: Finding[] = [];

  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i]!;

    if (options.verbose) {
      process.stderr.write(
        chalk.dim(
          `  [${i + 1}/${batches.length}] rules ${batch.map((r) => r.id).join(", ")}\n`
        )
      );
    }

    let responseText: string;
    try {
      responseText = await callProvider(
        options,
        apiKey,
        buildSystem(batch),
        userContent
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      throw new Error(`API error on batch ${i + 1} (${options.provider}): ${msg}`);
    }

    const batchFindings = parseFindings(responseText, batch);

    if (options.verbose && batchFindings.length > 0) {
      process.stderr.write(
        chalk.yellow(`    → ${batchFindings.length} finding(s)\n`)
      );
    }

    allFindings.push(...batchFindings);
  }

  const filtered = allFindings.filter(
    (f) => SEVERITY_ORDER[f.severity] <= minOrder
  );

  return filtered.sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );
}
