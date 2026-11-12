#!/usr/bin/env python3
"""Expose the current Wazuh Streamable HTTP MCP server as a local stdio MCP server.

Claude Code starts this bridge as a subprocess. The bridge exchanges the configured
read-only Wazuh API key for a short-lived bearer token, forwards MCP tools/list and
tools/call, detokenizes tool arguments, and scrubs Wazuh results before returning them.
"""
import asyncio
import json
import logging
import os
import sys
import time
import traceback
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlsplit, urlunsplit

import httpx2
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client
from mcp.server import Server
from mcp.server.stdio import stdio_server

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import privacy

logging.basicConfig(stream=sys.stderr, level=logging.ERROR)


class _NoRedirect(HTTPRedirectHandler):
    """Do not forward the Wazuh API key to a redirect target."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def token_endpoint(mcp_url):
    parsed = urlsplit(mcp_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("WAZUH_MCP_URL must be an absolute http(s) URL")
    path = parsed.path.rstrip("/")
    if path.endswith("/mcp"):
        path = path[:-4]
    return urlunsplit((parsed.scheme, parsed.netloc, path + "/auth/token", "", ""))


def get_bearer_token(mcp_url, api_key):
    endpoint = token_endpoint(mcp_url)
    body = json.dumps({"api_key": api_key}).encode("utf-8")
    request = Request(endpoint, data=body, headers={"Content-Type": "application/json"})
    try:
        with build_opener(_NoRedirect).open(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        raise RuntimeError("Wazuh MCP authentication failed; check the URL and read-only API key") from exc
    token = payload.get("access_token")
    if not isinstance(token, str) or not token:
        raise RuntimeError("Wazuh MCP token endpoint returned no access token")
    return token


def audit(**event):
    event.update(ts=time.strftime("%Y-%m-%dT%H:%M:%S"), epoch=time.time(), server="wazuh")
    try:
        with open(os.path.join(privacy.BASE, "audit.log"), "a", encoding="utf-8") as log:
            log.write(json.dumps(event, ensure_ascii=False) + "\n")
    except OSError:
        pass


def scrub_result(result):
    """Scrub MCP text and structured content using the existing privacy rules."""
    envelope = {"result": result.model_dump(mode="json", by_alias=True, exclude_none=True)}
    privacy.scrub_response(envelope)
    rendered = json.dumps(envelope["result"], ensure_ascii=False)
    tokens = sorted({match.group(0) for match in privacy.TOKEN_RE.finditer(rendered)})
    audit(
        event="scrubbed",
        chars=len(rendered),
        tokens=tokens,
        redactions=rendered.count("[REDACTED"),
        withheld=rendered.count("full_log withheld"),
        truncated=rendered.count("[truncated]"),
    )
    return types.CallToolResult.model_validate(envelope["result"])


async def serve(mcp_url, api_key):
    bearer = await asyncio.to_thread(get_bearer_token, mcp_url, api_key)
    timeout = httpx2.Timeout(30, read=300)
    async with httpx2.AsyncClient(
        headers={"Authorization": "Bearer " + bearer},
        timeout=timeout,
        follow_redirects=False,
    ) as http_client:
        async with streamable_http_client(mcp_url, http_client=http_client) as (read, write):
            async with ClientSession(read, write) as upstream:
                await upstream.initialize()

                async def list_tools(_ctx, params):
                    remote_params = types.PaginatedRequestParams(cursor=params.cursor) if params and params.cursor else None
                    result = await upstream.list_tools(params=remote_params)
                    return types.ListToolsResult(tools=result.tools, next_cursor=result.next_cursor)

                async def call_tool(_ctx, params):
                    args = privacy.detokenise_obj(params.arguments or {})
                    audit(tool=params.name, decision="forwarded")
                    try:
                        result = await upstream.call_tool(params.name, args)
                    except Exception as exc:
                        audit(event="upstream_error", tool=params.name, error=type(exc).__name__)
                        return types.CallToolResult(
                            content=[types.TextContent(type="text", text="Wazuh MCP request failed; check the Wazuh MCP service and its logs.")],
                            is_error=True,
                        )
                    return scrub_result(result)

                local = Server("wazuh-soc-assistant-privacy-bridge", on_list_tools=list_tools, on_call_tool=call_tool)
                async with stdio_server() as (local_read, local_write):
                    await local.run(local_read, local_write, local.create_initialization_options())


def main():
    mcp_url = os.environ.get("WAZUH_MCP_URL", "").strip()
    api_key = os.environ.get("WAZUH_MCP_API_KEY", "").strip()
    if not mcp_url or not api_key:
        print("WAZUH_MCP_URL and WAZUH_MCP_API_KEY are required", file=sys.stderr)
        return 2
    try:
        asyncio.run(serve(mcp_url, api_key))
    except Exception as exc:
        print("Wazuh privacy bridge failed: " + type(exc).__name__, file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
