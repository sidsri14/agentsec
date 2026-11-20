/**
 * Calculates unified security score and grade based on findings across all domains.
 */

export function calculateScorecard(findings, scannedCounts) {
  const counts = {
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  const domainCounts = {
    CONFIG: { total: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    TOOL: { total: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
    WORKFLOW: { total: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
  };

  for (const f of findings) {
    if (counts[f.severity] !== undefined) counts[f.severity]++;
    if (domainCounts[f.domain]) {
      domainCounts[f.domain].total++;
      if (domainCounts[f.domain][f.severity] !== undefined) {
        domainCounts[f.domain][f.severity]++;
      }
    }
  }

  // Scoring algorithm (Grade A+, A, B, C, F)
  let grade = "A+";
  let status = "SECURE";
  let description = "Zero critical or high security issues detected. Hardened baseline.";

  if (counts.HIGH >= 3) {
    grade = "F";
    status = "CRITICAL_RISK";
    description = "Multiple high-severity vulnerabilities detected. Immediate remediation required.";
  } else if (counts.HIGH >= 1 || counts.MEDIUM >= 4) {
    grade = "C";
    status = "ELEVATED_RISK";
    description = "High-severity or multiple medium-severity findings detected.";
  } else if (counts.MEDIUM >= 1 || counts.LOW >= 5) {
    grade = "B";
    status = "MODERATE_RISK";
    description = "Medium or low-severity policy warnings present.";
  } else if (counts.LOW >= 1) {
    grade = "A";
    status = "LOW_RISK";
    description = "Minor hygiene improvements suggested. No high or medium vulnerabilities.";
  }

  // Calculate percentage health score [0 - 100]
  // High: -25 pts, Medium: -10 pts, Low: -3 pts
  const deductions = counts.HIGH * 25 + counts.MEDIUM * 10 + counts.LOW * 3;
  const score = Math.max(0, 100 - deductions);

  return {
    grade,
    score,
    status,
    description,
    counts,
    domainCounts,
    scannedCounts,
  };
}
