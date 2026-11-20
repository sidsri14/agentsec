#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { scan } from "../src/scanner.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = path.join(root, "test", "fixtures", "bad-project");
const outDir = path.join(root, "docs");
const outHtml = path.join(outDir, "sample-report.html");
const outIndex = path.join(outDir, "index.html");

const report = scan([fixture]);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const rows = report.findings
  .map(
    (f) => `
      <tr>
        <td><span class="sev ${f.severity.toLowerCase()}">${esc(f.severity)}</span></td>
        <td><code>${esc(f.domain)}</code></td>
        <td><code>${esc(f.ruleId)}</code></td>
        <td>line ${f.startLine}</td>
        <td><code>${esc(f.target)}</code></td>
        <td>${esc(f.message)}</td>
      </tr>`
  )
  .join("\n");

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>agentsec — Sample Unified Security Scorecard</title>
  <style>
    body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 1100px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; background: #fafafa; }
    h1 { font-size: 26px; margin-bottom: 4px; }
    .sub { color: #666; margin-bottom: 24px; }
    .card { background: #fff; border: 1px solid #e2e2e2; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.04); }
    .scorecard { display: flex; gap: 20px; align-items: center; }
    .grade-badge { font-size: 48px; font-weight: 800; padding: 10px 24px; border-radius: 12px; background: #ffe3e3; color: #b00020; border: 2px solid #b00020; }
    .metrics { font-size: 15px; }
    .domain-bar { display: grid; grid-template-columns: repeat(3, 1fr); gap: 15px; margin-top: 15px; }
    .domain-card { background: #f8f9fa; padding: 12px; border-radius: 6px; border: 1px solid #eee; }
    table { border-collapse: collapse; width: 100%; font-size: 14px; margin-top: 10px; }
    th, td { border-bottom: 1px solid #eee; padding: 10px 8px; text-align: left; vertical-align: top; }
    th { background: #f4f4f4; font-weight: 600; }
    code { font-family: ui-monospace, Consolas, monospace; font-size: 13px; }
    .sev { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 700; }
    .high { background: #ffe3e3; color: #b00020; }
    .medium { background: #fff3cd; color: #7a5b00; }
    .low { background: #e7f0ff; color: #0b4f9c; }
    .note { background: #eef6ff; border-left: 4px solid #005fb8; padding: 14px 18px; color: #003666; border-radius: 4px; margin-bottom: 20px; }
  </style>
</head>
<body>
  <h1>agentsec — Unified Agent Security Scorecard</h1>
  <div class="sub">Generated from an automated scan across MCP configs, tool manifests, and GitHub Actions workflows (synthetic test project).</div>

  <div class="card scorecard">
    <div class="grade-badge">${report.scorecard.grade}</div>
    <div class="metrics">
      <div style="font-size: 18px; font-weight: 700; color: #111;">Rule-based Score: ${report.scorecard.score}/100</div>
      <div style="color: #555; margin-top: 4px;">Static rule matches from a synthetic test project. Review findings in context; this score does not certify security or verify exploitability.</div>
      <div style="margin-top: 8px;">
        <span class="sev high">${report.scorecard.counts.HIGH} High</span> &nbsp;
        <span class="sev medium">${report.scorecard.counts.MEDIUM} Medium</span> &nbsp;
        <span class="sev low">${report.scorecard.counts.LOW} Low</span> &nbsp;·&nbsp;
        <strong>${report.findings.length} total findings</strong>
      </div>
    </div>
  </div>

  <div class="card">
    <h3 style="margin-top:0;">Static Rule Breakdown</h3>
    <div class="domain-bar">
      <div class="domain-card">
        <strong>1. MCP Configurations</strong><br>
        Findings: ${report.scorecard.domainCounts.CONFIG.total}<br>
        <span style="font-size:12px; color:#666;">High: ${report.scorecard.domainCounts.CONFIG.HIGH} | Med: ${report.scorecard.domainCounts.CONFIG.MEDIUM}</span>
      </div>
      <div class="domain-card">
        <strong>2. Tool Manifests</strong><br>
        Findings: ${report.scorecard.domainCounts.TOOL.total}<br>
        <span style="font-size:12px; color:#666;">High: ${report.scorecard.domainCounts.TOOL.HIGH} | Med: ${report.scorecard.domainCounts.TOOL.MEDIUM}</span>
      </div>
      <div class="domain-card">
        <strong>3. CI/CD Workflows</strong><br>
        Findings: ${report.scorecard.domainCounts.WORKFLOW.total}<br>
        <span style="font-size:12px; color:#666;">High: ${report.scorecard.domainCounts.WORKFLOW.HIGH} | Med: ${report.scorecard.domainCounts.WORKFLOW.MEDIUM}</span>
      </div>
    </div>
  </div>

  <div class="card">
    <h2 style="margin-top:0;">Static Rule Findings</h2>
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Domain</th>
          <th>Rule</th>
          <th>Line</th>
          <th>Target</th>
          <th>Security Finding</th>
        </tr>
      </thead>
      <tbody>
        ${rows}
      </tbody>
    </table>
  </div>

  <div class="note">
    <strong>AI Agent &amp; MCP Static Security Review — starting at USD150:</strong>
    One surface, up to five configuration/workflow files or ten tool definitions, with a finding report,
    corrected examples, SARIF export and one recheck. Estimated delivery is one week after scope and a funded milestone are agreed.
    Static inspection only; no live exploitation, production access or guarantee of a fully secure system.
    Independent AI-assisted work, followed by technical review and automated checks.
    <a href="https://contra.com/s/RBAMObQB-ai-agent-and-mcp-static-security-review-single-surface">Inquire on Contra</a>;
    communication, contracting and payment for that engagement stay on Contra.
    <a href="https://github.com/sidsri14/agentsec/blob/main/PAID_OFFER.md">Scope and terms</a>.
  </div>
</body>
</html>
`;

fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(outHtml, html, "utf8");
fs.writeFileSync(outIndex, html, "utf8");
console.log(`Wrote ${outHtml} and ${outIndex} with ${report.findings.length} findings.`);
