"""Real MCP stdio handshake test, not a mocked FastMCP service test."""
from __future__ import annotations

import asyncio
import os
import sys

import pytest


def test_mcp_stdio_handshake_discovers_and_calls_execute_command(tmp_path):
    mcp = pytest.importorskip("mcp")
    from mcp import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    async def exercise_server() -> None:
        environment = {**os.environ, "SAFEAGENT_LOG": str(tmp_path / "mcp-audit.jsonl")}
        parameters = StdioServerParameters(command=sys.executable, args=["-m", "safeagent.mcp_server"], env=environment, cwd=os.getcwd())
        async with stdio_client(parameters) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                tool = next(item for item in tools.tools if item.name == "execute_command")
                assert "command" in tool.inputSchema["properties"]
                assert "user_request" in tool.inputSchema["properties"]
                result = await session.call_tool("execute_command", {"command": "echo safeagent-mcp-handshake"})
                assert not result.isError

    asyncio.run(exercise_server())
    assert (tmp_path / "mcp-audit.jsonl").exists()
