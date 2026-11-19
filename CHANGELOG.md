# Changelog

Notable changes to this project are recorded here so they are easy to review between commits. There is no formal release numbering yet.

## Unreleased — stable MCP integration update

### Changed

- Updated the Wazuh integration from the previous stdio setup to the Wazuh MCP Server `5.0.0` Streamable HTTP endpoint.
- Added `wazuh_http_bridge.py`, which obtains a short-lived bearer token, forwards Wazuh tool calls, detokenizes queries, and scrubs returned data before Claude receives it.
- Updated the Wazuh `.env` example for the current TLS, bearer authentication, read-only scope, and toolset settings.
- Pinned the local bridge dependencies to MCP Python SDK `2.3.0` and `httpx2` `2.16.0`.
- Pinned the Shodan MCP command to `@burtthecoder/mcp-shodan` `1.0.37` and kept its local privacy proxy focused on Shodan requests.
- Reworked the README setup steps for the selected integrations, including installing the Wazuh MCP server directly from the user's fork and registering both MCP servers with Claude Code.
- Documented installing and running the Wazuh MCP server from source for the fresh-machine test.
- Clarified that `privacy_config.json` is optional, described the built-in defaults, and explained how to add organization-specific terms later.
- Made the Wazuh source-install commands initialize their default paths so they work in a fresh terminal session.
- Corrected the Wazuh MCP source checkout to use its actual `v5.0.0` Git tag; `5.0.0` remains the release and package version.
- Documented using the user's Wazuh MCP fork's `main` branch as the install source; upstream changes only enter it after deliberate sync or merge and testing.
- Added Flask API smoke tests and documented local checks plus a live Wazuh query for a complete first-run verification.
- Kept VM networking and browser access instructions generic rather than tied to a cloud provider.

### Verification

- Python compilation passed for the app, privacy modules, bridge, and test files.
- `python test_privacy.py` passed its sanitization and round-trip checks.
- `python -m unittest test_app.py test_wazuh_http_bridge.py` passed: Flask API smoke tests and bridge authentication, tool discovery/calls, detokenization, and response scrubbing against a local mock MCP service.
- The Wazuh MCP Server `v5.0.0` source checkout installed successfully in a clean Python 3.12 virtual environment, and `python -m wazuh_mcp_server --help` ran successfully.
- Against the actual Wazuh MCP Server `v5.0.0` process with test-only credentials, this repo's bridge authenticated and listed 35 read-only tools; write actions and web search were absent.
- `pip check` and `git diff --check` passed.
- The live Wazuh deployment has not been tested as part of this update; validate it with your own Manager and Indexer before relying on it operationally.
