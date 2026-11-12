"""Local protocol test for the HTTP-to-stdio Wazuh privacy bridge."""
import asyncio
import json
import os
import socket
import unittest
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from mcp import ClientSession, types
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.server import Server
from starlette.applications import Starlette
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

import privacy

ROOT = Path(__file__).resolve().parent
PYTHON = ROOT / "venv" / "bin" / "python"
BRIDGE = ROOT / "wazuh_http_bridge.py"
UPSTREAM_ARGUMENTS = []


async def _list_tools(_ctx, _params):
    return types.ListToolsResult(tools=[types.Tool(
        name="echo_agent",
        description="Returns a sample agent record",
        input_schema={
            "type": "object",
            "properties": {"hostname": {"type": "string"}},
            "required": ["hostname"],
        },
    )])


async def _call_tool(_ctx, params):
    UPSTREAM_ARGUMENTS.append(params.arguments)
    data = {"hostname": params.arguments["hostname"], "source_ip": "10.23.4.5"}
    return types.CallToolResult(content=[types.TextContent(type="text", text=json.dumps(data))])


class _RequireBearer(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path.startswith("/mcp") and request.headers.get("authorization") != "Bearer test-bearer-token":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


async def _token(request):
    data = await request.json()
    if data.get("api_key") != "wazuh_test_readonly_key":
        return JSONResponse({"error": "invalid key"}, status_code=401)
    return JSONResponse({"access_token": "test-bearer-token", "expires_in": 86400})


class WazuhHTTPBridgeTest(unittest.TestCase):
    def test_token_exchange_bridge_list_detokenize_and_scrub(self):
        asyncio.run(self._run_bridge())

    async def _run_bridge(self):
        UPSTREAM_ARGUMENTS.clear()
        server = Server("test-wazuh", on_list_tools=_list_tools, on_call_tool=_call_tool)
        http_mcp_app = server.streamable_http_app()

        @asynccontextmanager
        async def lifespan(_app):
            async with server.session_manager.run():
                yield

        app = Starlette(routes=[
            Route("/auth/token", _token, methods=["POST"]),
            Mount("/", app=http_mcp_app),
        ], lifespan=lifespan)
        app.add_middleware(_RequireBearer)

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        upstream_server = uvicorn.Server(uvicorn.Config(app, log_level="warning"))
        server_task = asyncio.create_task(upstream_server.serve(sockets=[sock]))
        try:
            for _ in range(100):
                if upstream_server.started:
                    break
                await asyncio.sleep(0.02)
            self.assertTrue(upstream_server.started, "mock Wazuh MCP HTTP service did not start")

            host = "bridge-test.example.invalid"
            host_token = privacy._token_for("HOST", host)
            env = {
                "PATH": os.environ.get("PATH", ""),
                "WAZUH_MCP_URL": f"http://127.0.0.1:{port}/mcp",
                "WAZUH_MCP_API_KEY": "wazuh_test_readonly_key",
            }
            async with stdio_client(StdioServerParameters(
                command=str(PYTHON), args=[str(BRIDGE)], env=env, cwd=str(ROOT),
            )) as (read, write):
                async with ClientSession(read, write) as client:
                    await client.initialize()
                    tools = await client.list_tools()
                    self.assertEqual([tool.name for tool in tools.tools], ["echo_agent"])
                    result = await client.call_tool("echo_agent", {"hostname": host_token})

            self.assertEqual(UPSTREAM_ARGUMENTS, [{"hostname": host}])
            text = result.content[0].text
            self.assertNotIn(host, text)
            self.assertNotIn("10.23.4.5", text)
            self.assertIn(host_token, text)
            self.assertIn("INT_IP_", text)
        finally:
            upstream_server.should_exit = True
            await server_task
            sock.close()


if __name__ == "__main__":
    unittest.main()
