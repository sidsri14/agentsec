/**
 * Unified Multi-Domain Agent Scanner
 */
import fs from "node:fs";
import path from "node:path";
import { scanMcpConfig } from "./scanners/config.js";
import { scanToolManifest } from "./scanners/tool.js";
import { scanWorkflow } from "./scanners/workflow.js";
import { calculateScorecard } from "./scorecard.js";
import { SEVERITY_ORDER } from "./rules.js";

const SKIP_DIRS = new Set(["node_modules", ".git", ".cache", "dist", "build", "coverage", ".venv", "venv", "target"]);

export function discoverFiles(inputs) {
  const discovered = {
    configs: [],
    tools: [],
    workflows: [],
    totalScanned: 0,
  };

  function walk(currentPath) {
    let stat;
    try {
      stat = fs.statSync(currentPath);
    } catch {
      return;
    }

    if (stat.isDirectory()) {
      const baseName = path.basename(currentPath);
      if (SKIP_DIRS.has(baseName)) return;

      let entries;
      try {
        entries = fs.readdirSync(currentPath, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        walk(path.join(currentPath, entry.name));
      }
    } else if (stat.isFile()) {
      discovered.totalScanned++;
      const lower = currentPath.toLowerCase();

      // GitHub Actions workflow
      if ((lower.endsWith(".yml") || lower.endsWith(".yaml")) && currentPath.includes(".github")) {
        discovered.workflows.push(currentPath);
      } else if (lower.endsWith(".json")) {
        try {
          const raw = fs.readFileSync(currentPath, "utf8");
          const doc = JSON.parse(raw);

          // Check if MCP config
          if (doc.mcpServers || doc.servers || lower.includes("mcp") || lower.includes("claude_desktop")) {
            discovered.configs.push({ file: currentPath, doc, raw });
          }

          // Check if Tool manifest
          if (Array.isArray(doc) || doc.tools || doc.functions) {
            discovered.tools.push({ file: currentPath, doc, raw });
          }
        } catch {
          // Ignore unparseable JSON files
        }
      }
    }
  }

  for (const input of inputs) {
    walk(input);
  }

  return discovered;
}

export function scan(inputs) {
  const discovered = discoverFiles(inputs);
  const findings = [];

  // 1. Scan Configs
  for (const item of discovered.configs) {
    const res = scanMcpConfig(item.doc, item.file, item.raw);
    findings.push(...res);
  }

  // 2. Scan Tools
  for (const item of discovered.tools) {
    const res = scanToolManifest(item.doc, item.file, item.raw);
    findings.push(...res);
  }

  // 3. Scan Workflows
  for (const file of discovered.workflows) {
    try {
      const raw = fs.readFileSync(file, "utf8");
      const res = scanWorkflow(raw, file);
      findings.push(...res);
    } catch {
      // Ignore read errors
    }
  }

  // Deduplicate and sort
  const seen = new Set();
  const dedupedFindings = [];
  for (const f of findings) {
    const key = `${f.ruleId}:${f.file}:${f.target}:${f.startLine}`;
    if (!seen.has(key)) {
      seen.add(key);
      dedupedFindings.push(f);
    }
  }

  dedupedFindings.sort((a, b) => {
    const s = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (s !== 0) return s;
    return a.ruleId.localeCompare(b.ruleId);
  });

  const scannedCounts = {
    totalFiles: discovered.totalScanned,
    configs: discovered.configs.length,
    tools: discovered.tools.length,
    workflows: discovered.workflows.length,
  };

  const scorecard = calculateScorecard(dedupedFindings, scannedCounts);

  return {
    tool: { name: "agentsec", version: "0.1.0" },
    timestamp: new Date().toISOString(),
    scorecard,
    findings: dedupedFindings,
  };
}
