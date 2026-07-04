import asyncio
import json
import os
from pathlib import Path

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client


async def probe_server(name: str, command: str, args: list[str], cwd: str | None = None):
    params = StdioServerParameters(command=command, args=args, env=os.environ.copy())
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.list_tools()
            tools = []
            for tool in getattr(result, "tools", []):
                annotations = getattr(tool, "annotations", None)
                tools.append(
                    {
                        "name": getattr(tool, "name", None),
                        "description": getattr(tool, "description", None),
                        "annotations": annotations.model_dump() if hasattr(annotations, "model_dump") else str(annotations),
                    }
                )
            return {"name": name, "tools": tools}


async def main():
    workspace = Path(__file__).resolve().parent.parent
    sample_file = workspace / "sample_manifest.json"
    sample_file.write_text('{"name":"temp"}', encoding="utf-8")

    servers = [
        ("filesystem", "npx", ["-y", "@modelcontextprotocol/server-filesystem", str(workspace)]),
        ("github", "npx", ["-y", "@modelcontextprotocol/server-github"]),
    ]

    results = []
    for name, command, args in servers:
        try:
            result = await probe_server(name, command, args, str(workspace))
            results.append(result)
        except Exception as exc:
            results.append({"name": name, "error": str(exc)})

    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
