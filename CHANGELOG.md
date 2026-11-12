# Changelog

Notable changes to this project are recorded here so they are easy to review between commits. There is no formal release numbering yet.

## Unreleased — stable MCP integration update

### Changed

- Updated the Wazuh integration from the previous stdio setup to the Wazuh MCP Server `5.0.0` Streamable HTTP endpoint.
- Added `wazuh_http_bridge.py`, which obtains a short-lived bearer token, forwards Wazuh tool calls, detokenizes queries, and scrubs returned data before Claude receives it.
- Updated the Wazuh `.env` example for the current TLS, bearer authentication, read-only scope, and toolset settings.
- Pinned the local bridge dependencies to MCP Python SDK `2.3.0` and `httpx2` `2.16.0`.
- Pinned the Shodan MCP command to `@burtthecoder/mcp-shodan` `1.0.37` and kept its local privacy proxy focused on Shodan requests.
- Reworked the README setup steps for the selected versions, including cloning the tagged Wazuh release and registering both MCP servers with Claude Code.
- Documented installing and running the Wazuh MCP server from source for the fresh-machine test.

### Verification

- Python compilation passed for the app, privacy modules, bridge, and bridge test.
- `python test_privacy.py` passed its sanitization and round-trip checks.
- `python -m unittest test_wazuh_http_bridge.py` passed against a local mock MCP service, covering authentication, tool discovery/calls, and response scrubbing.
- The live Wazuh deployment has not been tested as part of this update; validate it with your own Manager and Indexer before relying on it operationally.
