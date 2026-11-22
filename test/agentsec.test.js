import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan, RULES, formatHuman, formatJson, formatSarif, run, EXIT } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BAD_PROJECT = path.join(__dirname, "fixtures", "bad-project");
const GOOD_PROJECT = path.join(__dirname, "fixtures", "good-project");

test("RULES has 27 unique registered rules across 3 domains", () => {
  assert.equal(RULES.length, 27);
  const domains = new Set(RULES.map((r) => r.domain));
  assert.deepEqual([...domains].sort(), ["CONFIG", "TOOL", "WORKFLOW"]);

  const ids = new Set(RULES.map((r) => r.id));
  assert.equal(ids.size, 27);
});

test("bad-project triggers findings across all three domains", () => {
  const report = scan([BAD_PROJECT]);
  assert.ok(report.findings.length >= 8, `Expected at least 8 findings, got ${report.findings.length}`);

  const domainsHit = new Set(report.findings.map((f) => f.domain));
  assert.ok(domainsHit.has("CONFIG"), "Should trigger CONFIG findings");
  assert.ok(domainsHit.has("TOOL"), "Should trigger TOOL findings");
  assert.ok(domainsHit.has("WORKFLOW"), "Should trigger WORKFLOW findings");
});

test("bad-project receives Grade F with score < 50", () => {
  const report = scan([BAD_PROJECT]);
  assert.equal(report.scorecard.grade, "F");
  assert.equal(report.scorecard.status, "CRITICAL_RISK");
  assert.ok(report.scorecard.score < 50, `Expected score < 50, got ${report.scorecard.score}`);
  assert.ok(report.scorecard.counts.HIGH >= 3, "Expected at least 3 high severity findings");
});

test("good-project receives Grade A+ with 100 health score and 0 findings", () => {
  const report = scan([GOOD_PROJECT]);
  assert.equal(report.findings.length, 0);
  assert.equal(report.scorecard.grade, "A+");
  assert.equal(report.scorecard.status, "SECURE");
  assert.equal(report.scorecard.score, 100);
});

test("formatJson produces valid JSON with scorecard", () => {
  const report = scan([BAD_PROJECT]);
  const jsonStr = formatJson(report);
  const parsed = JSON.parse(jsonStr);

  assert.equal(parsed.tool.name, "agentsec");
  assert.ok(parsed.scorecard.grade);
  assert.ok(Array.isArray(parsed.findings));
});

test("formatSarif produces valid SARIF 2.1.0 output", () => {
  const report = scan([BAD_PROJECT]);
  const sarifStr = formatSarif(report);
  const sarif = JSON.parse(sarifStr);

  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].tool.driver.name, "agentsec");
  assert.ok(sarif.runs[0].results.length > 0);
});

test("formatHuman produces readable terminal scorecard", () => {
  const report = scan([BAD_PROJECT]);
  const output = formatHuman(report);

  assert.ok(output.includes("AGENTSEC UNIFIED SECURITY SCORECARD"));
  assert.ok(output.includes("Overall Security Grade : [ F ]"));
  assert.ok(output.includes("MCP Configurations"));
  assert.ok(output.includes("Agent Tool Manifests"));
  assert.ok(output.includes("CI/CD Workflows"));
});

test("CLI exit codes correctly report security posture", () => {
  const exitBad = run(["scan", BAD_PROJECT, "--fail-on", "C"]);
  assert.equal(exitBad, EXIT.VULNERABILITIES);

  const exitGood = run(["scan", GOOD_PROJECT, "--fail-on", "C"]);
  assert.equal(exitGood, EXIT.OK);

  const exitRules = run(["rules"]);
  assert.equal(exitRules, EXIT.OK);
});

test("action.yml exists and defines valid composite GitHub Action", async () => {
  const fs = await import("node:fs");
  const actionPath = path.join(__dirname, "..", "action.yml");
  assert.ok(fs.existsSync(actionPath), "action.yml must exist at repository root");

  const content = fs.readFileSync(actionPath, "utf8");
  assert.ok(content.includes("using: \"composite\""));
  assert.ok(content.includes("bin/agentsec.js"));
  assert.ok(content.includes("inputs:"));
});

test("new CONFIG rules MC006, MC007, MC008, MC009 detect vulnerabilities", async () => {
  const { scanMcpConfig } = await import("../src/scanners/config.js");

  // MC006: broad filesystem root
  const fsConfig = {
    mcpServers: {
      files: { command: "npx", args: ["-y", "@modelcontextprotocol/server-filesystem", "/"] }
    }
  };
  const fsRes = scanMcpConfig(fsConfig, "test-mcp.json");
  assert.ok(fsRes.some((f) => f.ruleId === "MC006"), "Should detect MC006 broad filesystem root");

  // MC007: wildcard tool permissions
  const wildcardConfig = {
    mcpServers: {
      alltools: { command: "node", args: ["dist/server.js"], tools: ["*"] }
    }
  };
  const wcRes = scanMcpConfig(wildcardConfig, "test-mcp.json");
  assert.ok(wcRes.some((f) => f.ruleId === "MC007"), "Should detect MC007 wildcard tool permission");

  // MC008: hardcoded secret in args
  const secretArgConfig = {
    mcpServers: {
      authServer: { command: "node", args: ["dist/server.js", "--api-key=sk-ant-api03-abcdef123456789"] }
    }
  };
  const saRes = scanMcpConfig(secretArgConfig, "test-mcp.json");
  assert.ok(saRes.some((f) => f.ruleId === "MC008"), "Should detect MC008 secret in args");

  // MC009: raw interpreter without script
  const rawPyConfig = {
    mcpServers: {
      repl: { command: "python3", args: ["-u"] }
    }
  };
  const pyRes = scanMcpConfig(rawPyConfig, "test-mcp.json");
  assert.ok(pyRes.some((f) => f.ruleId === "MC009"), "Should detect MC009 raw interpreter without script");
});

test("new TOOL rules TS008, TS009 detect length and homoglyphs", async () => {
  const { scanToolManifest } = await import("../src/scanners/tool.js");

  // TS008: excessive description
  const longTool = [
    {
      name: "verbose_tool",
      description: "A".repeat(1050),
      inputSchema: { type: "object", properties: {} }
    }
  ];
  const t8Res = scanToolManifest(longTool, "tools.json");
  assert.ok(t8Res.some((f) => f.ruleId === "TS008"), "Should detect TS008 excessive description length");

  // TS009: non-ASCII / homoglyph tool name
  const spoofedTool = [
    {
      name: "bаsh", // Cyrillic а (U+0430)
      description: "A normal shell utility.",
      inputSchema: { type: "object", properties: {} }
    }
  ];
  const t9Res = scanToolManifest(spoofedTool, "tools.json");
  assert.ok(t9Res.some((f) => f.ruleId === "TS009"), "Should detect TS009 non-ASCII character in name");
});

test("new WORKFLOW rules FG008, FG009 detect self-hosted and missing permissions", async () => {
  const { scanWorkflow } = await import("../src/scanners/workflow.js");

  // FG008: self-hosted on pull_request
  const selfHostedYml = `
name: Untrusted PR
on: pull_request
jobs:
  test:
    runs-on: self-hosted
    steps:
      - run: npm test
`;
  const shRes = scanWorkflow(selfHostedYml, ".github/workflows/pr.yml");
  assert.ok(shRes.some((f) => f.ruleId === "FG008"), "Should detect FG008 self-hosted runner");
  assert.ok(shRes.some((f) => f.ruleId === "FG009"), "Should detect FG009 missing permissions block");
});

