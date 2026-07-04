# Finding 002 — High: Overprivileged Capability Surface in MCP Tools

- Severity: HIGH
- Affected surface: MCP tools with combined read/write/network permissions
- Attack vector: Privilege abuse through agentic tool execution

## Summary

A single tool can be configured to combine destructive and cross-boundary capabilities such as filesystem write and network access. In an agent-driven workflow, this creates an oversized execution surface that can be misused once a tool is invoked.

## Why it matters

This weakens least-privilege enforcement and expands the blast radius of a single tool invocation. The more capabilities a tool carries, the more impact an injected instruction or misrouted action can have.

## Remediation

- Split capabilities into narrow, purpose-specific tools
- Validate tool scope declarations against the intended action
- Require approval for tools that combine write and network behavior
