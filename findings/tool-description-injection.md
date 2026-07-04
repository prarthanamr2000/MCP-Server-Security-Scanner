# Finding 001 — Critical: Tool Description Injection in MCP Tool Metadata

- Severity: CRITICAL
- Affected surface: MCP tool descriptions and agent-facing metadata
- Attack vector: Prompt injection / instruction override via tool metadata

## Summary

The scanner identifies tool descriptions that contain overt instruction override language such as "ignore previous instructions", "bypass approval", or "exfiltrate secrets". In an agentic workflow, this material can be interpreted as a trusted directive and can influence downstream tool execution.

## Why it matters

This is a high-impact trust-boundary issue because the tool definition itself becomes an injection vector. The model may treat the metadata as authoritative even when it conflicts with policy.

## Remediation

- Strip instruction-like language from tool descriptions
- Require explicit approval for state-changing or cross-boundary actions
- Enforce tool metadata sanitization before exposure to the model
