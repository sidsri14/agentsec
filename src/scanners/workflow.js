/**
 * Domain Scanner: GitHub Actions CI/CD Workflows (.github/workflows/*.yml)
 */

export function scanWorkflow(rawContent, filePath) {
  const findings = [];
  const lines = rawContent.split(/\r?\n/);

  let hasPullRequestTarget = false;
  let inRunBlock = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNum = i + 1;
    const trimmed = line.trim();

    if (/pull_request_target\s*:?/.test(line)) {
      hasPullRequestTarget = true;
    }

    // FG001: Unpinned action
    const usesMatch = line.match(/^\s*(?:-\s*)?uses:\s*([^#\s]+)/);
    if (usesMatch) {
      const actionRef = usesMatch[1];
      if (!actionRef.startsWith("./") && !actionRef.startsWith("docker://")) {
        const parts = actionRef.split("@");
        const ref = parts[1];
        if (!ref || !/^[0-9a-f]{40}$/i.test(ref)) {
          findings.push({
            ruleId: "FG001",
            domain: "WORKFLOW",
            severity: "HIGH",
            file: filePath,
            target: actionRef,
            value: actionRef,
            message: `Action '${actionRef}' is unpinned. Pin to an exact 40-character commit SHA.`,
            startLine: lineNum,
          });
        }
      }
    }

    // FG002: pull_request_target with PR checkout
    if (hasPullRequestTarget && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.sha\s*\}\}/.test(line)) {
      findings.push({
        ruleId: "FG002",
        domain: "WORKFLOW",
        severity: "HIGH",
        file: filePath,
        target: "pull_request_target checkout",
        value: trimmed,
        message: `Untrusted PR code checked out inside pull_request_target workflow. Pwn-request vulnerability.`,
        startLine: lineNum,
      });
    }

    // FG003: Script injection via untrusted event expression in run
    if (/^\s*run:\s*\|?/.test(line) || inRunBlock) {
      if (/^\s*run:\s*\|?/.test(line)) inRunBlock = true;
      if (inRunBlock && line.length > 0 && !line.startsWith(" ") && !line.startsWith("\t")) {
        inRunBlock = false;
      }

      if (/\$\{\{\s*github\.event\.(issue\.(title|body)|pull_request\.(title|body)|comment\.body|head_commit\.message)\s*\}\}/.test(line)) {
        findings.push({
          ruleId: "FG003",
          domain: "WORKFLOW",
          severity: "HIGH",
          file: filePath,
          target: "run: script",
          value: trimmed,
          message: `Untrusted event text directly interpolated into shell script. Pass via env: instead.`,
          startLine: lineNum,
        });
      }
    }

    // FG004: permissions: write-all
    if (/^\s*permissions:\s*write-all\b/.test(line)) {
      findings.push({
        ruleId: "FG004",
        domain: "WORKFLOW",
        severity: "MEDIUM",
        file: filePath,
        target: "permissions: write-all",
        value: trimmed,
        message: `Workflow grants global write-all permissions. Restrict to minimal contents: read.`,
        startLine: lineNum,
      });
    }

    // FG005: Hardcoded credential
    if (/^\s*[A-Z0-9_]*(TOKEN|KEY|SECRET|PASSWORD)\s*:\s*["']?(ghp_[a-zA-Z0-9]{16,}|sk-[a-zA-Z0-9_-]{12,}|[a-zA-Z0-9_\-\.]{32,})["']?/.test(line)) {
      findings.push({
        ruleId: "FG005",
        domain: "WORKFLOW",
        severity: "HIGH",
        file: filePath,
        target: "env credential",
        value: "(masked credential)",
        message: `Hardcoded credential found in workflow env block. Use secrets context.`,
        startLine: lineNum,
      });
    }

    // FG006: curl | bash
    if (/curl\s+[^\n|]+\|\s*(ba|z)?sh/i.test(line)) {
      findings.push({
        ruleId: "FG006",
        domain: "WORKFLOW",
        severity: "MEDIUM",
        file: filePath,
        target: "curl | bash",
        value: trimmed,
        message: `Remote script piped directly into shell. Verify checksums or vendor scripts locally.`,
        startLine: lineNum,
      });
    }

    // FG007: actions/checkout without persist-credentials: false
    if (/uses:\s*actions\/checkout@/i.test(line)) {
      // Look ahead up to 5 lines for persist-credentials
      let hasPersistFalse = false;
      for (let j = i + 1; j < Math.min(lines.length, i + 8); j++) {
        if (/persist-credentials:\s*false/i.test(lines[j])) {
          hasPersistFalse = true;
          break;
        }
        if (/uses:|steps:/i.test(lines[j]) && !lines[j].includes("persist-credentials")) {
          break;
        }
      }
      if (!hasPersistFalse) {
        findings.push({
          ruleId: "FG007",
          domain: "WORKFLOW",
          severity: "LOW",
          file: filePath,
          target: "actions/checkout",
          value: trimmed,
          message: `actions/checkout does not explicitly disable persist-credentials. Set persist-credentials: false.`,
          startLine: lineNum,
        });
      }
    }

    // FG008: Self-hosted runner used on untrusted event
    if (/(pull_request|pull_request_target|issues|issue_comment)/i.test(rawContent)) {
      if (/runs-on:\s*(\[.*self-hosted.*\]|self-hosted)/i.test(line)) {
        findings.push({
          ruleId: "FG008",
          domain: "WORKFLOW",
          severity: "HIGH",
          file: filePath,
          target: "runs-on",
          value: trimmed,
          message: `Self-hosted runner used on untrusted PR or issue event.`,
          startLine: lineNum,
        });
      }
    }
  }

  // FG009: Missing explicit top-level permissions block
  if (!/^\s*permissions\s*:/m.test(rawContent)) {
    findings.push({
      ruleId: "FG009",
      domain: "WORKFLOW",
      severity: "MEDIUM",
      file: filePath,
      target: "permissions",
      value: "(missing permissions)",
      message: `Workflow lacks an explicit top-level permissions block. Enforce least privilege with permissions: contents: read.`,
      startLine: 1,
    });
  }

  return findings;
}
