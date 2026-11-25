# Changelog

Notable project changes are recorded here so they are easy to review between commits. There is no formal release numbering yet.

## Unreleased — replication guide and service setup

### Changed

- Clarified the first-install sequence for the SOC Assistant, the maintained Wazuh MCP fork, Shodan MCP, Claude Code API-key authentication, and remote browser access.
- Added copy/paste Bash commands to create the Wazuh Manager API `readonly` user and a least-privilege Indexer user, role, and mapping. Passwords are prompted without echo and JSON is escaped before requests are sent.
- Made the Indexer setup block require an explicit `INDEXER_IP` replacement rather than defaulting to localhost, and named the credential prompt as the Wazuh Indexer `admin` password.
- Made the Manager API account setup require an explicit `MANAGER_IP` replacement, added instructions for locating the `wazuh` API password in the assisted-installer archive, and added a clearly labeled password prompt that keeps the secret out of shell history and curl arguments.
- Added networking guidance for distributed and all-in-one deployments, including when localhost works, the Dashboard's `opensearch.hosts` setting, service ports, and the distinction between bind addresses and port conflicts.
- Clarified Wazuh Manager API password requirements and made the user-creation step report Wazuh's failure details instead of raising an `IndexError` when no user is returned.
- Simplified the Indexer account setup so it asks once for the Indexer admin password and reuses it through a protected temporary curl config for user, role, and mapping creation.
- Clarified that the MCP service unit and launcher come from the SOC Assistant checkout, while the Wazuh MCP virtual environment and `.env` must be created in the preceding install step.
- Added systemd units for the Flask app and Wazuh MCP server. Both run in the background, start at boot, and write service logs to the system journal; the app service requires the MCP service.
- Added a launcher that reads the maintained fork's `.env` and starts its Streamable HTTP service on loopback.
- Stored the Anthropic API key once in a mode-600 file outside the repository. The app service loads it alongside absolute Claude CLI and Node.js `npx` paths, so restarts do not require re-entry or shell exports.
- Added service-install guards for missing templates, launcher, virtual environments, credentials, and unreplaced username placeholders.
- Clarified SSH tunnel authentication using the VM's existing username, host, private key, or SSH alias. Explained that `ssh -N` opens no remote shell and documented `Permission denied (publickey)`.
- Clarified that privacy configuration is optional and can be tailored later, improved `/ready` troubleshooting, and expanded third-party credits.
- The integration uses the project maintainer's Wazuh MCP fork `main` branch, while upstream changes remain separate until review and compatibility testing. Shodan MCP `1.0.37` and the local MCP Python SDK `2.3.0` remain recorded in the dependency files.

### Verification

- Earlier build verification recorded Python compilation, privacy checks, bridge/app unit tests, package checks, and MCP discovery against the maintained fork at commit `e751871`.
- On the user's test VM, `/ready` returned HTTP 200 with Manager, Indexer, memory, and MCP healthy. The Flask systemd service was active and its UI returned HTTP 200.
- The full browser-to-Claude-to-Wazuh query and a fresh-VM run of the new Wazuh MCP systemd service still need confirmation.
- In this update, all 28 README Bash blocks passed `bash -n`; `deploy/run_wazuh_mcp_server.py` passed Python compilation; both rendered systemd units passed `systemd-analyze verify`; `git diff --check` passed.
