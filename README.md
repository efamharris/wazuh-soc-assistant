# Wazuh SOC Assistant

A single-user proof of concept for asking SOC triage questions in a local browser UI. The Flask app runs Claude Code headlessly and connects to Wazuh and Shodan through local stdio MCP servers. A local privacy layer masks internal identifiers, scrubs Wazuh results, blocks private or placeholder lookups to Shodan, and restores masked values in the analyst-facing answer.

This repository contains the current application and its required privacy components. It does not include the community Wazuh MCP server source, a Wazuh deployment, API credentials, or machine-wide Claude Code policy files.

## Scope

- Flask UI bound to `127.0.0.1:8080` by default.
- One analyst at a time; the UI has no login and must remain loopback-only.
- Read-only Wazuh queries and Shodan enrichment through stdio MCP servers.
- Local chat history and pseudonym mappings are retained for up to seven days.
- The app passes Wazuh and Shodan as allowed tools and blocks shell, file-editing, and web tools in its Claude Code invocation.
- Response actions are outside the demo scope. Use read-only Wazuh and Indexer credentials; server-side permissions remain the access control.
- Machine-wide Claude Code restrictions and the optional prompt-guard hook are not installed by this repository.

Treat answers as triage assistance and verify findings in Wazuh. This is a demo build, not a production deployment guide.

## Requirements

- Ubuntu 22.04 or newer
- Python 3.10+
- Node.js 24 and npm/npx
- Claude Code CLI authenticated with an Anthropic API key
- A Wazuh deployment and a dedicated read-only API account
- A Shodan API key
- The Wazuh MCP server at the commit recorded in `integrations/wazuh-mcp-server.lock`

## Setup

1. Clone this repository and create a virtual environment:

   ```bash
   python3 -m venv venv
   . venv/bin/activate
   pip install -r requirements.txt
   ```

2. Create a local privacy configuration and set your values before using the assistant:

   ```bash
   cp privacy_config.example.json privacy_config.json
   chmod 600 privacy_config.json
   ```

   Add your public IP ranges and sensitive organisation terms. Keep the local file private; it is excluded from Git.

3. Install the pinned Wazuh MCP server and configure its local environment:

   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   git checkout 960133dc8cd1cc909c6d79bc3bcaeeee583758e2
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt
   cp /path/to/wazuh-soc-assistant/integrations/wazuh-mcp-server.env.example .env
   chmod 600 .env
   ```

   Edit `.env` with your dedicated read-only Wazuh API and Indexer credentials. Then register both MCP servers through `privacy_proxy.py`, following the current user-level setup from the build guide. The Shodan command uses `@burtthecoder/mcp-shodan@1.0.34`.

   The Wazuh registration command shape is:

   ```bash
   claude mcp add --scope user --transport stdio wazuh -- \
     /usr/bin/python3 /path/to/wazuh-soc-assistant/privacy_proxy.py wazuh \
     /path/to/Wazuh-MCP-Server/mcp_wrapper.sh --stdio
   ```

   The Shodan registration command shape is:

   ```bash
   read -rsp 'Shodan API key: ' SHODAN_KEY; echo
   claude mcp add --scope user --transport stdio shodan \
     -e "SHODAN_API_KEY=$SHODAN_KEY" -- \
     /usr/bin/python3 /path/to/wazuh-soc-assistant/privacy_proxy.py shodan \
     npx -y @burtthecoder/mcp-shodan@1.0.34
   unset SHODAN_KEY
   ```

   Store credentials using your local secret-management approach. Do not commit MCP configuration containing API keys or passwords.

4. Read the Anthropic API key without putting it in shell history, then start the app:

   ```bash
   read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY; echo
   export ANTHROPIC_API_KEY
   python app.py
   ```

5. Open <http://127.0.0.1:8080>. Check `claude mcp list` before sending a query. For a persistent local service, adapt `deploy/soc-assistant.service.example` to your installation and user.

## Runtime files

The app creates `history.db`, `pseudo.db`, and `audit.log` beside the application. These files can contain conversation text, pseudonym mappings, and tool-call metadata; keep them local and protected. `.gitignore` excludes them.

## Repository contents

- `app.py`, `static/index.html`: Flask chat application and UI.
- `privacy.py`, `privacy_plus.py`: masking, response scrubbing, and privacy rules.
- `privacy_proxy.py`: stdio proxy for Wazuh and Shodan MCP traffic.
- `privacy_notes.py`: privacy-filter summary appended to answers.
- `privacy_config.example.json`: safe starter configuration; edit the local copy before use.
- `integrations/`: pinned upstream integration metadata and a credential-free environment template.
- `test_privacy.py`: the privacy-layer self-check supplied with the build.
- `deploy/`: service-unit example matching the current build-guide update.

## License

This project is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE). Third-party components are governed by their respective licenses.

## Updating the build

Keep the tracked tree limited to files that are in active use. Put machine-local state, credentials, chat databases, logs, virtual environments, and generated assets outside commits.
