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

## 📊 Executive Scorecard

When run, `agentsec` evaluates all discovered agent components and emits a unified letter grade and domain breakdown:

```text
================================================================================
  AGENTSEC UNIFIED SECURITY SCORECARD v0.1.0
================================================================================
  Overall Security Grade : [ A+ ]  Score: 100/100
  Health Status          : SECURE
  Summary                : Zero critical or high security issues detected. Hardened baseline.
--------------------------------------------------------------------------------
  DOMAIN AUDIT BREAKDOWN:
    • MCP Configurations    : 0 findings (0 High, 0 Med, 0 Low)
    • Agent Tool Manifests  : 0 findings (0 High, 0 Med, 0 Low)
    • CI/CD Workflows       : 0 findings (0 High, 0 Med, 0 Low)
--------------------------------------------------------------------------------
  ✓ Zero security vulnerabilities detected across all scanned agent components.
================================================================================
```

---

## 📋 Rule Catalog (19 Rules Across 3 Domains)

| ID | Domain | Severity | Title |
|---|---|---|---|
| **MC001** | `CONFIG` | HIGH | Unpinned package in npx / uvx / pip command |
| **MC002** | `CONFIG` | HIGH | Hardcoded secret or credential in env block |
| **MC003** | `CONFIG` | HIGH | Cleartext HTTP / WS remote MCP endpoint |
| **MC004** | `CONFIG` | MEDIUM | Dangerous command flag in server arguments |
| **MC005** | `CONFIG` | LOW | Missing explicit command in stdio server config |
| **TS001** | `TOOL` | HIGH | Instruction-like prompt injection text in tool description |
| **TS002** | `TOOL` | HIGH | Invisible Unicode control characters in tool metadata |
| **TS003** | `TOOL` | HIGH | Credential or secret in tool input parameters |
| **TS004** | `TOOL` | MEDIUM | Unbounded additionalProperties allowed in tool schema |
| **TS005** | `TOOL` | MEDIUM | Read-only named tool performs mutation or execution |
| **TS006** | `TOOL` | HIGH | Tool name impersonates a system built-in (bash, sudo) |
| **TS007** | `TOOL` | LOW | Sensitive string parameter lacks length constraint |
| **FG001** | `WORKFLOW` | HIGH | Unpinned GitHub Action referenced by mutable ref |
| **FG002** | `WORKFLOW` | HIGH | pull_request_target trigger combined with untrusted PR checkout |
| **FG003** | `WORKFLOW` | HIGH | Untrusted event data interpolated directly into shell script |
| **FG004** | `WORKFLOW` | MEDIUM | Workflow grants global write-all permissions |
| **FG005** | `WORKFLOW` | HIGH | Hardcoded secret or credential in workflow env block |
| **FG006** | `WORKFLOW` | MEDIUM | Remote script piped directly into shell |
| **FG007** | `WORKFLOW` | LOW | actions/checkout without persist-credentials: false |

---

## 🚀 CI/CD & SARIF Integration

Generate a SARIF 2.1.0 file directly compatible with GitHub Advanced Security / Code Scanning:

```bash
node bin/agentsec.js scan . --format sarif > agentsec.sarif
```

---

## 📄 License
MIT © Siddharth Srivastava
