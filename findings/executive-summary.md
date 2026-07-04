# Executive Summary

## Research posture

This repository evaluates MCP servers as emerging attack surfaces in agentic AI systems. The focus is not on conventional web vulnerabilities alone, but on how tool descriptions, permission scopes, and tool responses can alter the trust model between an agent and its environment.

## High-severity findings documented

- Critical: Tool-description injection and instruction override language
- Critical: Unauthenticated exposure of privileged endpoints
- High: Overprivileged tool surfaces enabling destructive or cross-boundary actions
- High: Trust-boundary erosion through policy-bypass language in metadata
- High: Repository mutation capabilities exposed to agentic workflows without strong approval gates

## Assessment

These findings are intended to demonstrate why MCP integrations require stronger guardrails than traditional API clients, especially when state-changing tools are exposed to an LLM-driven workflow.
