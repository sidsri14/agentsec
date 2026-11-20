/**
 * CLI command runner for agentsec
 */
import { scan } from "./scanner.js";
import { formatHuman, formatJson, formatSarif } from "./format.js";
import { RULES } from "./rules.js";

export const EXIT = {
  OK: 0,
  VULNERABILITIES: 1,
  ERROR: 2,
};

export function run(args) {
  if (args.length === 0 || args.includes("-h") || args.includes("--help")) {
    console.log(`
agentsec v0.1.0 — Unified Security Scorecard & Linter for Autonomous Agent Ecosystems

Usage:
  agentsec scan <path...> [options]
  agentsec rules
  agentsec --version
  agentsec --help

Options:
  -f, --format <human|json|sarif>   Output report format (default: human)
      --fail-on <A|B|C|F>           Fail with exit code 1 if grade is at or below this tier (default: C)
      --quiet                       Suppress human summary output

Examples:
  agentsec scan .
  agentsec scan . --format sarif > agentsec.sarif
  agentsec scan src/ config/ .github/workflows
`);
    return EXIT.OK;
  }

  if (args.includes("-v") || args.includes("--version")) {
    console.log("agentsec v0.1.0");
    return EXIT.OK;
  }

  const command = args[0];

  if (command === "rules") {
    console.log("=== AGENTSEC REGISTERED SECURITY RULES (19 RULES) ===\n");
    for (const r of RULES) {
      console.log(`[${r.id}] [${r.domain}] ${r.severity.padEnd(6)} : ${r.title}`);
      console.log(`       Fix: ${r.remediation}\n`);
    }
    return EXIT.OK;
  }

  if (command === "scan") {
    const paths = [];
    let format = "human";
    let failOn = "C";

    for (let i = 1; i < args.length; i++) {
      const arg = args[i];
      if (arg === "-f" || arg === "--format") {
        format = args[++i] || "human";
      } else if (arg === "--fail-on") {
        failOn = args[++i] || "C";
      } else if (!arg.startsWith("-")) {
        paths.push(arg);
      }
    }

    if (paths.length === 0) paths.push(".");

    const report = scan(paths);

    if (format === "json") {
      console.log(formatJson(report));
    } else if (format === "sarif") {
      console.log(formatSarif(report));
    } else {
      console.log(formatHuman(report));
    }

    const GRADE_SEVERITY = { "A+": 0, A: 1, B: 2, C: 3, F: 4 };
    const reportSeverity = GRADE_SEVERITY[report.scorecard.grade] ?? 0;
    const thresholdSeverity = GRADE_SEVERITY[failOn] ?? 3;

    if (reportSeverity >= thresholdSeverity && reportSeverity > 0) {
      return EXIT.VULNERABILITIES;
    }
    return EXIT.OK;
  }

  console.error(`Unknown command: ${command}. Run agentsec --help for usage.`);
  return EXIT.ERROR;
}
