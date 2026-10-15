#!/usr/bin/env -S npx tsx
import * as fs from "node:fs";
import * as path from "node:path";
import { extractExpressRoutes } from "@scanner/adapter-express";
import { analyzeAccessControl } from "@scanner/analyzer-access-control";
import type { Finding, RouteInfo, ScanResult } from "@scanner/core";

const c = {
  bold: (s: string) => `\x1b[1m${s}\x1b[0m`,
  dim: (s: string) => `\x1b[2m${s}\x1b[0m`,
  red: (s: string) => `\x1b[31m${s}\x1b[0m`,
  green: (s: string) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s: string) => `\x1b[33m${s}\x1b[0m`,
  cyan: (s: string) => `\x1b[36m${s}\x1b[0m`,
};
const stripAnsi = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

const USAGE = `Usage :
  scanner routes <dossier> [--json]   Carte des routes et de leurs contrôles d'accès
  scanner scan   <dossier> [--json]   Failles détectées (A01 contrôle d'accès)`;

export function scan(root: string): ScanResult {
  const routes = extractExpressRoutes({ root });
  const findings = analyzeAccessControl(routes);
  return { root: path.resolve(root), framework: "express", routes, findings };
}

function main(argv: string[]): number {
  const [command, target] = argv;
  const json = argv.includes("--json");
  if (!command || !target || !["routes", "scan"].includes(command)) {
    console.error(USAGE);
    return 2;
  }
  if (!fs.existsSync(target)) {
    console.error(`Dossier introuvable : ${target}`);
    return 2;
  }

  const result = scan(target);

  if (json) {
    const payload = command === "routes" ? { routes: result.routes, findings: result.findings } : { findings: result.findings };
    console.log(JSON.stringify(payload, null, 2));
  } else if (command === "routes") {
    printRoutes(result.routes, result.findings);
  } else {
    printFindings(result.findings);
  }
  return result.findings.length > 0 && command === "scan" ? 1 : 0;
}

function printRoutes(routes: RouteInfo[], findings: Finding[]): void {
  const flagged = new Set(findings.map((f) => `${f.route.method} ${f.route.path}`));
  const rows = routes.map((r) => [
    flagged.has(`${r.method} ${r.path}`) ? c.red("!") : " ",
    c.bold(r.method),
    r.path,
    r.auth.authenticated ? c.green("oui") : c.yellow("non"),
    r.auth.roles.length ? r.auth.roles.join(",") : c.dim("-"),
    r.auth.ownership === "comparison" ? c.green("vérifié") : r.auth.ownership === "scoped-query" ? c.green("filtré") : c.dim("-"),
    c.dim(`${r.location.file}:${r.location.line}`),
  ]);
  const header = [" ", "MÉTHODE", "CHEMIN", "AUTH", "RÔLES", "PROPRIÉTAIRE", "DÉCLARÉE DANS"].map(c.bold);
  printTable([header, ...rows]);
  console.log();
  console.log(`${routes.length} routes, ${c.red(String(findings.length))} incohérence(s) d'accès. Détails : scanner scan <dossier>`);
}

function printFindings(findings: Finding[]): void {
  if (findings.length === 0) {
    console.log(c.green("Aucune incohérence de contrôle d'accès détectée."));
    return;
  }
  for (const f of findings) {
    const sev = f.severity === "critical" || f.severity === "high" ? c.red(f.severity.toUpperCase()) : c.yellow(f.severity.toUpperCase());
    console.log(`${sev}  ${c.bold(f.title)}  ${c.dim(`[${f.owasp} · ${f.cwe} · confiance ${f.confidence}]`)}`);
    console.log(`  ${c.cyan(`${f.route.method} ${f.route.path}`)}  ${c.dim(`${f.route.location.file}:${f.route.location.line}`)}`);
    console.log(`  ${f.message}`);
    for (const e of f.evidence) console.log(c.dim(`    · ${e}`));
    console.log();
  }
  console.log(`${findings.length} faille(s) détectée(s).`);
}

function printTable(rows: string[][]): void {
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => stripAnsi(r[i]).length)));
  for (const r of rows) {
    console.log(r.map((cell, i) => cell + " ".repeat(widths[i] - stripAnsi(cell).length)).join("  "));
  }
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]).endsWith(path.join("cli", "src", "index.ts"));
if (isDirectRun) process.exitCode = main(process.argv.slice(2));
