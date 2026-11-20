/**
 * Formatting outputs: Human, JSON, SARIF 2.1.0
 */

export function formatHuman(report) {
  const { scorecard, findings } = report;
  const lines = [];

  lines.push("================================================================================");
  lines.push(`  AGENTSEC UNIFIED SECURITY SCORECARD v${report.tool.version}`);
  lines.push("================================================================================");
  lines.push(`  Overall Security Grade : [ ${scorecard.grade} ]  Score: ${scorecard.score}/100`);
  lines.push(`  Health Status          : ${scorecard.status}`);
  lines.push(`  Summary                : ${scorecard.description}`);
  lines.push("--------------------------------------------------------------------------------");
  lines.push("  DOMAIN AUDIT BREAKDOWN:");
  lines.push(`    • MCP Configurations    : ${scorecard.domainCounts.CONFIG.total} findings (${scorecard.domainCounts.CONFIG.HIGH} High, ${scorecard.domainCounts.CONFIG.MEDIUM} Med, ${scorecard.domainCounts.CONFIG.LOW} Low)`);
  lines.push(`    • Agent Tool Manifests  : ${scorecard.domainCounts.TOOL.total} findings (${scorecard.domainCounts.TOOL.HIGH} High, ${scorecard.domainCounts.TOOL.MEDIUM} Med, ${scorecard.domainCounts.TOOL.LOW} Low)`);
  lines.push(`    • CI/CD Workflows       : ${scorecard.domainCounts.WORKFLOW.total} findings (${scorecard.domainCounts.WORKFLOW.HIGH} High, ${scorecard.domainCounts.WORKFLOW.MEDIUM} Med, ${scorecard.domainCounts.WORKFLOW.LOW} Low)`);
  lines.push("--------------------------------------------------------------------------------");

  if (findings.length === 0) {
    lines.push("  ✓ Zero security vulnerabilities detected across all scanned agent components.");
  } else {
    lines.push(`  DETECTED FINDINGS (${findings.length} total):`);
    for (const f of findings) {
      lines.push(`  [${f.severity.padEnd(6)}] ${f.ruleId} (${f.domain}) in ${f.file}:${f.startLine}`);
      lines.push(`          Target : ${f.target}`);
      lines.push(`          Issue  : ${f.message}`);
    }
  }

  lines.push("================================================================================");
  return lines.join("\n");
}

export function formatJson(report) {
  return JSON.stringify(report, null, 2);
}

export function formatSarif(report) {
  const sarifRules = [];
  const results = [];

  const seenRules = new Set();
  for (const f of report.findings) {
    if (!seenRules.has(f.ruleId)) {
      seenRules.add(f.ruleId);
      sarifRules.push({
        id: f.ruleId,
        name: f.ruleId,
        shortDescription: { text: f.message },
        defaultConfiguration: {
          level: f.severity === "HIGH" ? "error" : f.severity === "MEDIUM" ? "warning" : "note",
        },
      });
    }

    results.push({
      ruleId: f.ruleId,
      level: f.severity === "HIGH" ? "error" : f.severity === "MEDIUM" ? "warning" : "note",
      message: { text: f.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: f.file.replace(/\\/g, "/") },
            region: { startLine: f.startLine || 1 },
          },
        },
      ],
    });
  }

  const sarif = {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "agentsec",
            version: report.tool.version,
            informationUri: "https://github.com/sidsri14/agentsec",
            rules: sarifRules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}
