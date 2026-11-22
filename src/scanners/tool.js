/**
 * Domain Scanner: Agent Tool Manifests & Tool Descriptions
 */

const INSTRUCTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+instructions/i,
  /system\s+prompt/i,
  /do\s+not\s+(tell|alert|notify)\s+the\s+user/i,
  /send\s+(this\s+)?(token|secret|key|data|file)\s+to/i,
  /fetch\s+and\s+execute/i,
  /bypass\s+(safety|guardrails?|checks?)/i,
];

const INVISIBLE_UNICODE_REGEX = /[\u200B-\u200D\uFEFF\u202A-\u202E\u2066-\u2069]/g;
const PRIVILEGED_NAMES = new Set(["bash", "sh", "terminal", "exec", "sudo", "system", "root", "admin"]);

export function scanToolManifest(doc, filePath, rawText = "") {
  const findings = [];
  const tools = Array.isArray(doc)
    ? doc
    : Array.isArray(doc.tools)
    ? doc.tools
    : Array.isArray(doc.functions)
    ? doc.functions
    : null;

  if (!tools) return findings;

  for (const tool of tools) {
    if (!tool || typeof tool !== "object") continue;
    const name = tool.name || tool.function?.name || "";
    const description = tool.description || tool.function?.description || "";
    const schema = tool.inputSchema || tool.parameters || tool.function?.parameters || {};

    // TS001: Instruction-like text in description
    for (const pat of INSTRUCTION_PATTERNS) {
      if (pat.test(description)) {
        findings.push({
          ruleId: "TS001",
          domain: "TOOL",
          severity: "HIGH",
          file: filePath,
          target: name,
          value: description.slice(0, 60) + "...",
          message: `Tool '${name}' description contains prompt-injection instruction text matching ${pat}.`,
          startLine: 1,
        });
        break;
      }
    }

    // TS002: Invisible Unicode
    if (INVISIBLE_UNICODE_REGEX.test(name) || INVISIBLE_UNICODE_REGEX.test(description)) {
      findings.push({
        ruleId: "TS002",
        domain: "TOOL",
        severity: "HIGH",
        file: filePath,
        target: name,
        value: "U+InvisibleUnicode",
        message: `Tool '${name}' metadata contains invisible Unicode control characters.`,
        startLine: 1,
      });
    }

    // TS006: Privileged built-in impersonation
    if (PRIVILEGED_NAMES.has(name.toLowerCase())) {
      findings.push({
        ruleId: "TS006",
        domain: "TOOL",
        severity: "HIGH",
        file: filePath,
        target: name,
        value: name,
        message: `Tool name '${name}' impersonates a privileged system utility. Use a namespaced name.`,
        startLine: 1,
      });
    }

    // TS003: Credential in tool input schema
    const properties = schema.properties || {};
    for (const propName of Object.keys(properties)) {
      if (/^(api[_-]?key|password|token|secret|private[_-]?key)$/i.test(propName)) {
        findings.push({
          ruleId: "TS003",
          domain: "TOOL",
          severity: "HIGH",
          file: filePath,
          target: `${name}.${propName}`,
          value: propName,
          message: `Tool '${name}' exposes credential parameter '${propName}' directly in tool inputs.`,
          startLine: 1,
        });
      }

      // TS007: Unconstrained sensitive string
      const prop = properties[propName] || {};
      if (prop.type === "string" && !prop.maxLength && /^(command|code|script|sql|query|path)$/i.test(propName)) {
        findings.push({
          ruleId: "TS007",
          domain: "TOOL",
          severity: "LOW",
          file: filePath,
          target: `${name}.${propName}`,
          value: propName,
          message: `Sensitive input '${propName}' lacks a maxLength boundary.`,
          startLine: 1,
        });
      }
    }

    // TS004: Unbounded additionalProperties
    if (schema.type === "object" && schema.additionalProperties === true) {
      findings.push({
        ruleId: "TS004",
        domain: "TOOL",
        severity: "MEDIUM",
        file: filePath,
        target: name,
        value: "additionalProperties: true",
        message: `Tool '${name}' allows unconstrained additionalProperties. Set to false.`,
        startLine: 1,
      });
    }

    // TS005: Read-name mismatch with mutation
    if (/^(get|read|list|fetch|query)_/i.test(name) && /(delete|execute|remove|drop|kill|write)/i.test(description)) {
      findings.push({
        ruleId: "TS005",
        domain: "TOOL",
        severity: "MEDIUM",
        file: filePath,
        target: name,
        value: description.slice(0, 50) + "...",
        message: `Tool '${name}' has a read-only prefix but describes destructive operations in description.`,
        startLine: 1,
      });
    }

    // TS008: Excessive description length (> 1,024 chars)
    if (typeof description === "string" && description.length > 1024) {
      findings.push({
        ruleId: "TS008",
        domain: "TOOL",
        severity: "LOW",
        file: filePath,
        target: name,
        value: `${description.length} chars`,
        message: `Tool '${name}' description is excessively long (${description.length} chars > 1,024 max recommended).`,
        startLine: 1,
      });
    }

    // TS009: Non-ASCII or homoglyph character in tool name
    if (typeof name === "string" && /[^\x20-\x7E]/.test(name)) {
      findings.push({
        ruleId: "TS009",
        domain: "TOOL",
        severity: "HIGH",
        file: filePath,
        target: name,
        value: name,
        message: `Tool name '${name}' contains non-ASCII or homoglyph characters.`,
        startLine: 1,
      });
    }
  }

  return findings;
}
