# Real MCP Server Test Results

## Targets tested

1. @modelcontextprotocol/server-filesystem
2. @modelcontextprotocol/server-github

## Test approach

- Installed the packages locally with npm
- Connected to each server over MCP stdio
- Enumerated the real tool catalog exposed by each server
- Recorded the tool surface and mapped it to security-relevant behavior

## Observed findings

- Filesystem server exposed a wide set of read/write/edit/move/search tools that can affect local files and directories.
- GitHub server exposed repository-state-changing tools such as create/update file, create pull request, merge pull request, and branch creation.

## Security interpretation

These findings support the scanner's goal of identifying overprivileged MCP tool surfaces and verifying whether tool descriptions and capability boundaries are appropriate.
