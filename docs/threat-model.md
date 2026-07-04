# Threat Model for MCP Tooling

## Assets

- Tool descriptions and metadata
- Permission declarations and scope boundaries
- Tool responses and downstream agent context
- Network endpoints and repository mutation surfaces

## Threats

- Tool poisoning via hidden or conflicting instructions in tool descriptions
- Privilege escalation through overbroad permissions or implicit trust in tool metadata
- Prompt-injection style abuse in tool outputs and structured payloads
- Unauthorized access to privileged routes and sensitive state-changing operations

## Mitigations

- Sanitize tool descriptions and metadata before presentation to the agent
- Enforce least-privilege scopes and explicit approval gates for state-changing actions
- Isolate and validate tool outputs before they can influence downstream model behavior
- Require authentication and authorization for every privileged route and mutation action
