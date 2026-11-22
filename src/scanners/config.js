/**
 * Domain Scanner: MCP Server Configurations (mcp.json, claude_desktop_config.json, etc.)
 */
import { RULES } from "../rules.js";

const SECRET_KEY_PATTERNS = [
  /api[_-]?key/i,
  /auth[_-]?token/i,
  /secret/i,
  /password/i,
  /private[_-]?key/i,
  /access[_-]?token/i,
];

function maskSecret(val) {
  if (typeof val !== "string" || val.length <= 4) return "****";
  return val.slice(0, 2) + "****" + val.slice(-2);
}

export function scanMcpConfig(doc, filePath, rawText = "") {
  const findings = [];
  const servers = doc.mcpServers || doc.servers || (doc.command ? { root: doc } : null);
  if (!servers || typeof servers !== "object") return findings;

  for (const [serverName, server] of Object.entries(servers)) {
    if (!server || typeof server !== "object") continue;

    const command = server.command || "";
    const args = Array.isArray(server.args) ? server.args : [];
    const env = server.env || {};
    const url = server.url || "";

    // MC001: Unpinned package in npx / uvx / pip
    if (/^(npx|uvx|pipx?)$/i.test(command)) {
      for (const arg of args) {
        if (typeof arg !== "string" || arg.startsWith("-")) continue;
        if (!arg.includes("@") && !arg.includes("==") && !arg.includes(".js") && !arg.includes("/") && !arg.includes("\\")) {
          findings.push({
            ruleId: "MC001",
            domain: "CONFIG",
            severity: "HIGH",
            file: filePath,
            target: serverName,
            value: `${command} ${arg}`,
            message: `Unpinned package '${arg}' executed via ${command}. Pin to an exact version (@version).`,
            startLine: 1,
          });
        }
      }
    }

    // MC002: Hardcoded secret in env
    for (const [key, val] of Object.entries(env)) {
      if (typeof val === "string" && val.trim().length > 6) {
        const isKeySecret = SECRET_KEY_PATTERNS.some((p) => p.test(key));
        const isTokenValue = /^(sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{16,}|[a-zA-Z0-9_\-\.]{32,})$/.test(val.trim());
        if (isKeySecret || isTokenValue) {
          findings.push({
            ruleId: "MC002",
            domain: "CONFIG",
            severity: "HIGH",
            file: filePath,
            target: `${serverName}.env.${key}`,
            value: maskSecret(val),
            message: `Hardcoded credential found in env var '${key}'. Use environment variable substitution instead.`,
            startLine: 1,
          });
        }
      }
    }

    // MC003: Cleartext HTTP/WS endpoint
    if (url && (url.startsWith("http://") || url.startsWith("ws://"))) {
      if (!url.includes("localhost") && !url.includes("127.0.0.1") && !url.includes("[::1]")) {
        findings.push({
          ruleId: "MC003",
          domain: "CONFIG",
          severity: "HIGH",
          file: filePath,
          target: serverName,
          value: url,
          message: `Remote server URL '${url}' uses unencrypted transport. Use https:// or wss://.`,
          startLine: 1,
        });
      }
    }

    // MC004: Dangerous command flags
    for (const arg of args) {
      if (typeof arg === "string" && (/--dangerously/i.test(arg) || /--allow-all/i.test(arg) || /--no-sandbox/i.test(arg))) {
        findings.push({
          ruleId: "MC004",
          domain: "CONFIG",
          severity: "MEDIUM",
          file: filePath,
          target: serverName,
          value: arg,
          message: `Dangerous blanket bypass flag '${arg}' found in server arguments.`,
          startLine: 1,
        });
      }
    }

    // MC005: Missing command in stdio
    if (!url && !command) {
      findings.push({
        ruleId: "MC005",
        domain: "CONFIG",
        severity: "LOW",
        file: filePath,
        target: serverName,
        value: "(missing command)",
        message: `Server '${serverName}' lacks a command or URL definition.`,
        startLine: 1,
      });
    }

    // MC006: Over-broad filesystem root
    const serverLabel = `${serverName} ${command} ${args.join(" ")}`.toLowerCase();
    if (/(filesystem|desktop-commander|file.?system|\bgit\b|\bfiles\b)/i.test(serverLabel)) {
      for (const arg of args) {
        if (typeof arg === "string") {
          const trimmed = arg.trim();
          if (
            trimmed === "/" ||
            trimmed === "~" ||
            trimmed === "/root" ||
            trimmed === "/home" ||
            trimmed === "/Users" ||
            /^[A-Za-z]:[\\/]?$/.test(trimmed)
          ) {
            findings.push({
              ruleId: "MC006",
              domain: "CONFIG",
              severity: "MEDIUM",
              file: filePath,
              target: serverName,
              value: trimmed,
              message: `Filesystem server granted broad system root '${trimmed}'.`,
              startLine: 1,
            });
          }
        }
      }
    }

    // MC007: Wildcard tool permission
    const toolPerms = server.tools || server.allowedTools || (server.permissions && server.permissions.tools);
    if (
      toolPerms === "*" ||
      toolPerms === "all" ||
      (Array.isArray(toolPerms) && (toolPerms.includes("*") || toolPerms.includes("all")))
    ) {
      findings.push({
        ruleId: "MC007",
        domain: "CONFIG",
        severity: "MEDIUM",
        file: filePath,
        target: serverName,
        value: String(toolPerms),
        message: `Wildcard tool permission '${toolPerms}' granted to server '${serverName}'.`,
        startLine: 1,
      });
    }

    // MC008: Hardcoded credential in arguments
    const SECRET_ARG_RE = /^(--?token|--?api[_-]?key|--?password|--?secret|--?auth)[=:](.+)$/i;
    for (const arg of args) {
      if (typeof arg === "string") {
        const m = arg.match(SECRET_ARG_RE);
        const candidate = m ? m[2] : arg;
        if (/^(sk-[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{16,})$/.test(candidate) || (m && candidate.length >= 8)) {
          findings.push({
            ruleId: "MC008",
            domain: "CONFIG",
            severity: "HIGH",
            file: filePath,
            target: serverName,
            value: maskSecret(candidate),
            message: `Hardcoded credential found in command-line argument for '${serverName}'.`,
            startLine: 1,
          });
        }
      }
    }

    // MC009: Stdio server invokes raw interpreter without script argument
    const cmd = typeof command === "string" ? command.split(/[\\/]/).pop().toLowerCase() : "";
    const INTERPRETERS = new Set(["python", "python3", "node", "ruby", "perl", "php"]);
    if (INTERPRETERS.has(cmd)) {
      const hasScript = args.some(
        (a) => typeof a === "string" && !a.startsWith("-") && (a.includes(".") || a.includes("/"))
      );
      if (!hasScript) {
        findings.push({
          ruleId: "MC009",
          domain: "CONFIG",
          severity: "HIGH",
          file: filePath,
          target: serverName,
          value: `${command} ${args.join(" ")}`.trim(),
          message: `Interpreter '${cmd}' invoked without an explicit script file argument.`,
          startLine: 1,
        });
      }
    }
  }

  return findings;
}
