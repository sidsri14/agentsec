import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan, RULES, formatHuman, formatJson, formatSarif, run, EXIT } from "../src/index.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BAD_PROJECT = path.join(__dirname, "fixtures", "bad-project");
const GOOD_PROJECT = path.join(__dirname, "fixtures", "good-project");

test("RULES has 19 unique registered rules across 3 domains", () => {
  assert.equal(RULES.length, 19);
  const domains = new Set(RULES.map((r) => r.domain));
  assert.deepEqual([...domains].sort(), ["CONFIG", "TOOL", "WORKFLOW"]);

  const ids = new Set(RULES.map((r) => r.id));
  assert.equal(ids.size, 19);
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
