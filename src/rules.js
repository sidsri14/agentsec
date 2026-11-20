/**
 * Complete registry of agentsec security rules across all three domains:
 * - CONFIG: Model Context Protocol client/server configurations
 * - TOOL: Agent tool manifests and tool descriptions
 * - WORKFLOW: GitHub Actions CI/CD pipelines
 */

export const SEVERITY_ORDER = {
  HIGH: 0,
  MEDIUM: 1,
  LOW: 2,
  INFO: 3,
};

export const RULES = [
  // --- Domain: CONFIG (MCP Server Configurations) ---
  {
    id: "MC001",
    domain: "CONFIG",
    severity: "HIGH",
    title: "Unpinned package in npx / uvx / pip command",
    rationale: "Running unversioned remote packages executes latest unreviewed code on every launch, enabling supply-chain takeover.",
    remediation: "Pin packages to an exact tag or commit hash (e.g. npx -y @modelcontextprotocol/server-postgres@0.1.2).",
  },
  {
    id: "MC002",
    domain: "CONFIG",
    severity: "HIGH",
    title: "Hardcoded secret or credential in env block",
    rationale: "Committed API tokens and credentials in configuration files are easily leaked or exposed to untrusted subagents.",
    remediation: "Use environment variable expansion or secret managers rather than plaintext credential strings.",
  },
  {
    id: "MC003",
    domain: "CONFIG",
    severity: "HIGH",
    title: "Cleartext HTTP / WS remote MCP endpoint",
    rationale: "Remote MCP servers over plain HTTP or WS expose tool calls and responses to network eavesdropping and tampering.",
    remediation: "Always use HTTPS or WSS for remote MCP server connections.",
  },
  {
    id: "MC004",
    domain: "CONFIG",
    severity: "MEDIUM",
    title: "Dangerous command flag in server arguments",
    rationale: "Flags like --dangerously-skip-permissions or --allow-all grant blanket host access without human approval.",
    remediation: "Remove blanket bypass flags and use least-privilege scoping per server.",
  },
  {
    id: "MC005",
    domain: "CONFIG",
    severity: "LOW",
    title: "Missing explicit command in stdio server config",
    rationale: "Stdio servers without explicit command or args can produce undefined or platform-dependent execution.",
    remediation: "Specify an explicit binary command and pinned argument list.",
  },

  // --- Domain: TOOL (Tool Manifests & Prompt Injection) ---
  {
    id: "TS001",
    domain: "TOOL",
    severity: "HIGH",
    title: "Instruction-like text in tool description",
    rationale: "Tool descriptions are injected directly into LLM prompts. Imperative instructions can hijack agent behavior (tool poisoning).",
    remediation: "Rewrite the description as a neutral capability statement. Move behavioral guidelines to system prompts.",
  },
  {
    id: "TS002",
    domain: "TOOL",
    severity: "HIGH",
    title: "Invisible Unicode control characters in tool metadata",
    rationale: "Zero-width spaces, joiners, and bidi overrides hide instructions from human reviewers while affecting model parsing.",
    remediation: "Strip zero-width and bidi control characters from all tool names and descriptions.",
  },
  {
    id: "TS003",
    domain: "TOOL",
    severity: "HIGH",
    title: "Credential or secret in tool input parameters",
    rationale: "Exposing token or password fields directly to autonomous agent tool calls leads to accidental credential exfiltration.",
    remediation: "Store credentials securely in backend vaults; reference them by opaque identifiers.",
  },
  {
    id: "TS004",
    domain: "TOOL",
    severity: "MEDIUM",
    title: "Unbounded additionalProperties allowed in tool schema",
    rationale: "Permitting unconstrained additional properties allows prompt injections to pass malicious auxiliary arguments.",
    remediation: "Set additionalProperties: false on object schemas or explicitly define allowed properties.",
  },
  {
    id: "TS005",
    domain: "TOOL",
    severity: "MEDIUM",
    title: "Read-only named tool performs mutation or execution",
    rationale: "Naming a tool get_* or read_* while describing file deletion or code execution tricks approval policies.",
    remediation: "Align tool naming prefixes (get, read, create, delete, run) truthfully with actual capabilities.",
  },
  {
    id: "TS006",
    domain: "TOOL",
    severity: "HIGH",
    title: "Tool name impersonates a system built-in",
    rationale: "Naming tools bash, sudo, admin, or system tricks agents into treating untrusted third-party tools as native.",
    remediation: "Use namespaced identifiers that clearly identify the tool's domain (e.g. github_search).",
  },
  {
    id: "TS007",
    domain: "TOOL",
    severity: "LOW",
    title: "Sensitive string parameter lacks length constraint",
    rationale: "Unconstrained string parameters for code, query, or path can be used for denial-of-service or memory exhaustion.",
    remediation: "Add maxLength constraints on open-ended string input schemas.",
  },

  // --- Domain: WORKFLOW (GitHub Actions CI/CD) ---
  {
    id: "FG001",
    domain: "WORKFLOW",
    severity: "HIGH",
    title: "Unpinned GitHub Action referenced by mutable ref",
    rationale: "Using @v1 or @main allows attackers who compromise the action's repo to push malicious code into your CI.",
    remediation: "Pin third-party actions to an exact full-length commit SHA (e.g. actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683).",
  },
  {
    id: "FG002",
    domain: "WORKFLOW",
    severity: "HIGH",
    title: "pull_request_target trigger combined with untrusted PR checkout",
    rationale: "pull_request_target runs in the base context with repository secrets. Checking out PR code allows PR authors to exfiltrate secrets.",
    remediation: "Use pull_request for untrusted code builds; never check out untrusted pull requests inside pull_request_target jobs.",
  },
  {
    id: "FG003",
    domain: "WORKFLOW",
    severity: "HIGH",
    title: "Untrusted event data interpolated directly into shell script",
    rationale: "Directly interpolating ${{ github.event.issue.title }} into a run: bash block allows shell metacharacter command injection.",
    remediation: "Pass untrusted event fields via env: and reference them as environment variables (e.g. \"$TITLE\").",
  },
  {
    id: "FG004",
    domain: "WORKFLOW",
    severity: "MEDIUM",
    title: "Workflow grants global write-all permissions",
    rationale: "permissions: write-all grants broad write access across code, issues, and releases to any compromised step.",
    remediation: "Set top-level permissions: contents: read and elevate permissions only on the specific jobs that require them.",
  },
  {
    id: "FG005",
    domain: "WORKFLOW",
    severity: "HIGH",
    title: "Hardcoded secret or credential in workflow env block",
    rationale: "Committing literal access tokens or API keys exposes them in repository logs and history.",
    remediation: "Store credentials in GitHub Repository Secrets and reference via ${{ secrets.NAME }}.",
  },
  {
    id: "FG006",
    domain: "WORKFLOW",
    severity: "MEDIUM",
    title: "Remote script piped directly into shell",
    rationale: "curl ... | bash executes unverified remote scripts without integrity checking or auditability.",
    remediation: "Download, verify hash checksum, and execute reviewed scripts, or vendor dependencies into the repository.",
  },
  {
    id: "FG007",
    domain: "WORKFLOW",
    severity: "LOW",
    title: "actions/checkout without persist-credentials: false",
    rationale: "actions/checkout persists the GITHUB_TOKEN in the local git config by default, making it accessible to subsequent build steps.",
    remediation: "Add persist-credentials: false to actions/checkout steps unless subsequent git push actions explicitly require it.",
  },
];
