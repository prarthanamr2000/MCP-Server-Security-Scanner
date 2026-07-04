# Finding 003 — Critical: Unauthenticated Exposure of Privileged MCP Endpoints

- Severity: CRITICAL
- Affected surface: MCP server endpoints exposed without authentication
- Attack vector: Unauthorized access to privileged routes

## Summary

The scanner flags MCP server endpoints that are declared without authentication. When such endpoints are reachable by a client or agent, they bypass the first trust boundary and can expose privileged actions before any authorization check occurs.

## Why it matters

This is especially serious in agent-driven systems because the server may be indirectly invoked through a trusted tool chain. An exposed administrative route can become a pivot point once the model is given access to the surrounding environment.

## Remediation

- Require authentication for all privileged routes
- Deny anonymous access by default
- Enforce authorization checks for every state-changing endpoint
