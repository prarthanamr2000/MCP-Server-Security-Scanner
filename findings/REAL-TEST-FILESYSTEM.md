# Finding 004 — High: Filesystem MCP Server Exposes a Broad Destructive Tool Surface

- Severity: HIGH
- Target: @modelcontextprotocol/server-filesystem
- Test method: connected over MCP stdio and enumerated the live tool catalog using the real server implementation

## Summary

The filesystem server exposes a broad set of read, write, edit, move, search, and metadata operations. In an agentic workflow, this creates a large execution surface where a single misdirected tool call can modify files, move content, or enumerate sensitive paths.

## Why it matters

This is a material privilege boundary because the server exposes state-changing capability directly to an agent without any visible approval gate in the tool metadata. The risk is amplified when the model is operating in a workspace that contains credentials, source code, or internal documentation.

## Remediation

- Separate read-only and write-capable tools
- Enforce path allow-lists and per-action approval
- Restrict file-system access to narrowly scoped directories
