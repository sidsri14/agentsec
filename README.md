# agentsec 🛡️

**Unified Static Security Scorecard & Linter for Autonomous Agent Ecosystems**

[![Test](https://github.com/sidsri14/agentsec/actions/workflows/ci.yml/badge.svg)](https://github.com/sidsri14/agentsec/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-success.svg)](package.json)

`agentsec` is a lightweight, zero-dependency static security linter and scorecard generator designed for autonomous AI agent applications, Model Context Protocol (MCP) servers, and agentic workflows.

It automatically scans three critical attack surfaces:
1. **MCP Configurations (`CONFIG`)**: Unpinned packages, hardcoded credentials, cleartext endpoints, blanket bypass flags.
2. **Tool Manifests (`TOOL`)**: Tool-poisoning prompt injections, invisible Unicode triggers, credential parameters, unbounded schemas, built-in impersonation.
3. **CI/CD Workflows (`WORKFLOW`)**: GitHub Actions pwn-requests, script injection, global write permissions, curl-pipe-bash.

---

## ⚡ Quick Start

### Global Run via npx / node:
```bash
npx github:sidsri14/agentsec scan .
```

### Local Installation:
```bash
git clone https://github.com/sidsri14/agentsec.git
cd agentsec
npm test
node bin/agentsec.js scan .
```

---

## 📊 Rule-based Scorecard

`agentsec` summarizes static rule matches with a letter grade and domain breakdown. The grade is a heuristic, not a security certification. An empty finding list does not establish that the scanned system is secure or free of vulnerabilities.

Selected lines from a no-findings report:

```text
================================================================================
  AGENTSEC UNIFIED SECURITY SCORECARD v0.1.0
================================================================================
  Overall Security Grade : [ A+ ]  Score: 100/100
--------------------------------------------------------------------------------
  DOMAIN AUDIT BREAKDOWN:
    • MCP Configurations    : 0 findings (0 High, 0 Med, 0 Low)
    • Agent Tool Manifests  : 0 findings (0 High, 0 Med, 0 Low)
    • CI/CD Workflows       : 0 findings (0 High, 0 Med, 0 Low)
--------------------------------------------------------------------------------
================================================================================
```

---

The CLI also emits status and summary labels. Interpret those labels only within the documented rule set: static checks can miss issues and can flag patterns that are safe in context. Review findings before making changes. Runtime authorization, exploitability and resistance to prompt injection are not verified by this scan.

## 📋 Rule Catalog (27 Rules Across 3 Domains)

| ID | Domain | Severity | Title |
|---|---|---|---|
| **MC001** | `CONFIG` | HIGH | Unpinned package in npx / uvx / pip command |
| **MC002** | `CONFIG` | HIGH | Hardcoded secret or credential in env block |
| **MC003** | `CONFIG` | HIGH | Cleartext HTTP / WS remote MCP endpoint |
| **MC004** | `CONFIG` | MEDIUM | Dangerous command flag in server arguments |
| **MC005** | `CONFIG` | LOW | Missing explicit command in stdio server config |
| **MC006** | `CONFIG` | MEDIUM | Over-broad filesystem root granted to server |
| **MC007** | `CONFIG` | MEDIUM | Wildcard tool permission in server policy |
| **MC008** | `CONFIG` | HIGH | Hardcoded credential in server arguments |
| **MC009** | `CONFIG` | HIGH | Stdio server invokes raw interpreter without script argument |
| **TS001** | `TOOL` | HIGH | Instruction-like prompt injection text in tool description |
| **TS002** | `TOOL` | HIGH | Invisible Unicode control characters in tool metadata |
| **TS003** | `TOOL` | HIGH | Credential or secret in tool input parameters |
| **TS004** | `TOOL` | MEDIUM | Unbounded additionalProperties allowed in tool schema |
| **TS005** | `TOOL` | MEDIUM | Read-only named tool performs mutation or execution |
| **TS006** | `TOOL` | HIGH | Tool name impersonates a system built-in (bash, sudo) |
| **TS007** | `TOOL` | LOW | Sensitive string parameter lacks length constraint |
| **TS008** | `TOOL` | LOW | Excessive description length (> 1,024 characters) |
| **TS009** | `TOOL` | HIGH | Non-ASCII or homoglyph character in tool name |
| **FG001** | `WORKFLOW` | HIGH | Unpinned GitHub Action referenced by mutable ref |
| **FG002** | `WORKFLOW` | HIGH | pull_request_target trigger combined with untrusted PR checkout |
| **FG003** | `WORKFLOW` | HIGH | Untrusted event data interpolated directly into shell script |
| **FG004** | `WORKFLOW` | MEDIUM | Workflow grants global write-all permissions |
| **FG005** | `WORKFLOW` | HIGH | Hardcoded secret or credential in workflow env block |
| **FG006** | `WORKFLOW` | MEDIUM | Remote script piped directly into shell |
| **FG007** | `WORKFLOW` | LOW | actions/checkout without persist-credentials: false |
| **FG008** | `WORKFLOW` | HIGH | Self-hosted runner used on pull_request or untrusted event |
| **FG009** | `WORKFLOW` | MEDIUM | Workflow missing explicit top-level permissions block |

---

## 🚀 CI/CD & SARIF Integration

Generate a SARIF 2.1.0 file directly compatible with GitHub Advanced Security / Code Scanning:

```bash
node bin/agentsec.js scan . --format sarif > agentsec.sarif
```

---

## 📄 License
MIT © Siddharth Srivastava

## Paid services (fixed scope)

Bounded software services via no-signup Contra checkout: multi-repo CI reliability sprint (up to 5 repos, USD5,000 for one agreed milestone), checkout-link consistency gate (USD100), token-2022 CI/fee-math repair (USD150), BullMQ token-budget retrofit (USD300), one bounded OSS issue plus regression PR (USD75), and web3 starter CI harness (USD150).

All offers: https://sidsri14.github.io/implementation-packages.html | Request work (no signup): https://sidsri14.github.io/request-work.html

Proof: 25 merged upstream PRs / 30 total merged GitHub PRs; 201 passing tests across 15 owned repos. Independent, AI-assisted work; BCA student at Manipal University Jaipur, expected 2027, Lucknow, India. Advertised offers only, not received income; scope and written terms are agreed before any work starts.