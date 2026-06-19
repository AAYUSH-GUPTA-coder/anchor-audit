import { execSync } from "node:child_process";
import os from "node:os";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

export interface AuditMetadata {
  date: string;
  time: string;
  timestamp: string;
  model: string;
  provider: string;
  effort: string;
  cliVersion: string;
  project: string;
  gitCommit?: string;
  gitBranch?: string;
  os: string;
  durationMs: number;
  totalFiles: number;
  totalFindings: number;
}

function git(cmd: string): string | undefined {
  try {
    return execSync(cmd, {
      encoding: "utf8",
      stdio: ["pipe", "pipe", "ignore"],
      timeout: 2000,
    }).trim() || undefined;
  } catch {
    return undefined;
  }
}

function readVersion(): string {
  try {
    const pkgPath = join(dirname(fileURLToPath(import.meta.url)), "../package.json");
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8")) as { version?: string };
    return pkg.version ?? "0.1.0";
  } catch {
    return "0.1.0";
  }
}

export function buildMetadata(params: {
  model: string;
  provider: string;
  effort: string;
  project: string;
  startTime: Date;
  totalFiles: number;
  totalFindings: number;
}): AuditMetadata {
  const now = new Date();
  const iso = now.toISOString();

  return {
    date: iso.slice(0, 10),
    time: iso.slice(11, 19) + " UTC",
    timestamp: iso,
    model: params.model,
    provider: params.provider,
    effort: params.effort,
    cliVersion: readVersion(),
    project: params.project,
    gitCommit: git("git rev-parse --short HEAD"),
    gitBranch: git("git rev-parse --abbrev-ref HEAD"),
    os: `${os.type()} ${os.release()} (${os.arch()})`,
    durationMs: now.getTime() - params.startTime.getTime(),
    totalFiles: params.totalFiles,
    totalFindings: params.totalFindings,
  };
}
