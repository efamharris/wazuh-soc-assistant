# Wazuh SOC Assistant

A single-user demo for asking SOC triage questions through a local browser UI. The Flask app runs Claude Code headlessly and connects to Wazuh over Streamable HTTP through a local stdio privacy bridge, and to Shodan through a local stdio MCP proxy. Its local privacy layer masks internal identifiers, scrubs Wazuh results, blocks private or placeholder lookups to Shodan, and restores masked values in the analyst-facing answer.

This repository contains the assistant application and its privacy components. It does not include Wazuh or Shodan MCP server source code, a Wazuh deployment, API credentials, or machine-wide Claude Code policy files. Third-party MCP projects and the versions used by this build are identified below.

## Minimum system requirements

These are baseline requirements for one analyst using the app locally. The Wazuh deployment is expected to be on a separate reachable system; this minimum is not enough to host a Wazuh stack as well.

| Resource | Minimum / baseline |
| --- | --- |
| Operating system | 64-bit Ubuntu 24.04 or newer; commands below assume Bash. |
| CPU | 2 cores. This is a practical baseline for the Flask app and local MCP processes, not a benchmarked project limit. |
| Memory | 4 GB RAM. Claude Code documents 4 GB+ as its hardware minimum. |
| Free disk space | 8 GB for the checkouts, Python virtual environments, Node package cache, and logs. This is a practical allowance, not a measured minimum. |
| Network | Internet access for Claude and package downloads, plus network access from this machine to the Wazuh Manager and Indexer. |
| Browser | A modern browser on the same machine to open the local UI. |

The app, local bridge, and source-installed Wazuh MCP server need Python 3.11 or newer. This setup also needs the current Node.js LTS release with npm/npx, Git, and the latest Claude Code CLI authenticated to an account that can use Claude. You also need a Wazuh deployment with read-only Manager API and Indexer accounts, and a Shodan API key. The Wazuh MCP Server 5.0 line supports Wazuh 4.8 through 4.14.7. See [Anthropic's Claude Code system requirements](https://docs.anthropic.com/en/docs/claude-code/getting-started) for its documented OS, memory, software, and network requirements.

## Before you start

Run the commands in order, in the same terminal, unless a step says otherwise. Before using the assistant, customize only the items listed here:

| File or prompt | What you must supply |
| --- | --- |
| `privacy_config.json` | Your organization's public IP ranges and sensitive names/terms. |
| Wazuh MCP `.env` | Reachable Wazuh Manager and Indexer addresses, read-only credentials, and TLS settings that match your certificates. |
| Wazuh MCP API key | Generated read-only key; the local bridge uses it to obtain a short-lived bearer token. |
| Wazuh MCP source checkout | The pinned Wazuh MCP Server release, installed in its own Python virtual environment and configured with your Wazuh endpoints. |
| Shodan prompt | Your Shodan API key. |
| Anthropic prompt | Your Anthropic API key, unless Claude Code is already authenticated on this machine. |
| Path variables in Step 1 | Change them only if you choose a different directory from the defaults. |

Do not leave angle-bracket examples such as `<READ_ONLY_WAZUH_API_USER>` in place. Replace them with real values before starting the MCP server. Keep API keys and passwords out of committed files and shell command text.

## Install prerequisites on Ubuntu

These commands install Python, Git, curl, the current Node.js LTS release with npm/npx, and the latest Claude Code CLI. They assume Ubuntu 24.04 or newer, Bash, and an account allowed to use `sudo` for system packages. Ubuntu 24.04 supplies Python 3.12, which meets the Python 3.11 minimum for the MCP bridge.

First install Python and Git:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip git curl ca-certificates
```

Install the current Node.js LTS release with nvm. The Ubuntu archive may provide a different Node.js major version; nvm lets this guide select the current LTS line. The installer below is the tagged installer from the [nvm project](https://github.com/nvm-sh/nvm):

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.8/install.sh | bash
source ~/.bashrc
nvm install --lts
nvm alias default 'lts/*'
```

Check Node.js and npm are available and on the expected major version:

```bash
node --version
npm --version
npx --version
```

`node --version` should report an LTS release. npm and npx are installed with Node.js. If `nvm` is not found after installation, close and reopen the terminal, then run `source ~/.bashrc` and repeat the Node.js commands.

Install Claude Code globally for your user. Do not add `sudo` to the npm command:

```bash
npm install -g @anthropic-ai/claude-code@latest
claude --version
claude doctor
```

Authenticate Claude Code by running `claude` and following the sign-in prompts. When authentication finishes and the Claude prompt appears, enter `/exit` to return to the shell. Claude Code supports Anthropic Console authentication and eligible Claude subscriptions; see [Anthropic's setup guide](https://docs.anthropic.com/en/docs/claude-code/getting-started) for account details. If you choose API-key authentication instead, the later app-start step shows how to enter the key without echoing it.

Finally, confirm the required commands are available:

```bash
python3 --version
git --version
node --version
npm --version
npx --version
claude --version
```

If a command is missing, or Node.js is not on an LTS release, resolve that before continuing.

### Version and update policy

Python, Git, Node.js LTS, and Claude Code are installed from current supported releases. This build currently pins Wazuh MCP Server `5.0.0`, Shodan MCP `1.0.37`, and the MCP Python SDK `2.3.0` in [`integrations/wazuh-mcp-server.lock`](integrations/wazuh-mcp-server.lock) and `requirements.txt`. These pins make installs repeatable. When upstream releases change, review the release notes and compatibility requirements, update the related pins/configuration together, and run the end-to-end verification in this guide before using the update. Do not replace pins with floating `main` or `@latest` tags in a working deployment.

See [`CHANGELOG.md`](CHANGELOG.md) for a concise record of project changes and verification status.

## 1. Clone this repository

Run these commands from your home directory. They create `~/wazuh-soc-assistant`:

```bash
cd ~
git clone https://github.com/efamharris/wazuh-soc-assistant.git
cd ~/wazuh-soc-assistant
```

Keep this terminal open and define the paths used in the remaining commands:

```bash
export ASSISTANT_DIR="$HOME/wazuh-soc-assistant"
export WAZUH_MCP_DIR="$HOME/Wazuh-MCP-Server-5.0.0"
```

If you cloned either repository to another location, change the matching path above before continuing. All later commands use these variables, so keep them set in this terminal.

## 2. Install the assistant

```bash
cd "$ASSISTANT_DIR"
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp privacy_config.example.json privacy_config.json
chmod 600 privacy_config.json
```

Open the new file in a text editor:

```bash
nano "$ASSISTANT_DIR/privacy_config.json"
```

Replace the empty `own_public_ranges` array with your organization's public network ranges in CIDR notation (for example, `198.51.100.10/32` is a documentation-only example), and replace the empty `sensitive_terms` array with names or terms that should be masked. Keep the JSON syntax: values go in double quotes, separated by commas. The example is valid but has no organization-specific entries; leaving the arrays empty means those custom ranges or terms are not configured. Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X` in nano). Do not commit `privacy_config.json`.

## 3. Install the pinned Wazuh MCP release from source

This build uses the community [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) release `5.0.0`, pinned in [`integrations/wazuh-mcp-server.lock`](integrations/wazuh-mcp-server.lock). The server exposes Streamable HTTP. The local [`wazuh_http_bridge.py`](wazuh_http_bridge.py) connects to it, detokenizes Wazuh queries, and scrubs returned data before Claude receives it.

Clone the exact pinned Wazuh MCP release, create its own virtual environment, and install its Python package:

```bash
cd "$HOME"
git clone --branch 5.0.0 --depth 1 https://github.com/gensecaihq/Wazuh-MCP-Server.git "$WAZUH_MCP_DIR"
cd "$WAZUH_MCP_DIR"
git describe --tags --exact-match HEAD
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp "$ASSISTANT_DIR/integrations/wazuh-mcp-server.env.example" .env
chmod 600 .env
```

Edit the environment file:

```bash
nano "$WAZUH_MCP_DIR/.env"
```

Replace `WAZUH_HOST`, `WAZUH_USER`, and `WAZUH_PASS` with the reachable Manager address and a dedicated read-only API account. Replace `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, and `WAZUH_INDEXER_PASS` with the Indexer address and a dedicated read-only account. Change ports only if your Wazuh services use non-default ports. The example uses strict TLS verification; if your certificates are private, set `WAZUH_CA_BUNDLE` to the CA bundle's path on this VM. For a stock self-signed Manager certificate, set `WAZUH_ALLOW_SELF_SIGNED=true`; set `WAZUH_INDEXER_VERIFY_SSL=false` only if you deliberately accept the Indexer's certificate without verification. Do not leave angle-bracket placeholders. Save and exit nano.

Generate the production signing secret and the read-only MCP API key directly into `.env` without printing them to the terminal:

```bash
python3 - <<'PY'
from pathlib import Path
import secrets

env_path = Path(".env")
contents = env_path.read_text()
contents = contents.replace("AUTH_SECRET_KEY=<GENERATE_RANDOM_SECRET>", "AUTH_SECRET_KEY=" + secrets.token_hex(32))
contents = contents.replace("MCP_API_KEY=<GENERATE_READ_ONLY_API_KEY>", "MCP_API_KEY=wazuh_" + secrets.token_urlsafe(32))
if "<GENERATE_" in contents:
    raise SystemExit("Secret placeholders remain in .env; check the example values and try again")
env_path.write_text(contents)
PY
chmod 600 .env
```

Start the Wazuh MCP server in this terminal. Keep it running while testing the assistant; use a second SSH terminal for the remaining steps:

```bash
cd "$WAZUH_MCP_DIR"
source .venv/bin/activate
set -a
. ./.env
set +a
MCP_HOST=127.0.0.1 MCP_PORT=3000 ENVIRONMENT=production python -m wazuh_mcp_server
```

In the second SSH terminal, define the paths again and check readiness:

```bash
export ASSISTANT_DIR="$HOME/wazuh-soc-assistant"
export WAZUH_MCP_DIR="$HOME/Wazuh-MCP-Server-5.0.0"
curl -fsS http://127.0.0.1:3000/ready
```

The server listens on loopback port `3000`; leave it local. If `/ready` fails, inspect the server output in the first terminal and correct the Wazuh host, credentials, TLS settings, or network access before continuing.

The MCP server permits read-only tools through the `wazuh:read` key scope and exposes only the `alerts`, `agents`, `vulnerabilities`, `analysis`, `compliance`, and `system` toolsets. The `response` and `web_search` toolsets are not enabled.

## 4. Register the Wazuh privacy bridge

The bridge gets a short-lived bearer token from the local Wazuh MCP server using the read-only key. Claude Code stores the key in its local MCP configuration, so protect your local account and configuration files. If you are upgrading from the previous stdio Wazuh integration, remove that entry first:

```bash
claude mcp remove wazuh
```

Read the key from the protected `.env` and register the bridge. These commands assume the default URL and clone paths:

```bash
WAZUH_API_KEY="$(sed -n 's/^MCP_API_KEY=//p' "$WAZUH_MCP_DIR/.env")"
test -n "$WAZUH_API_KEY" || { echo "MCP_API_KEY is missing from .env" >&2; exit 1; }
claude mcp add --scope user --transport stdio wazuh \
  -e WAZUH_MCP_URL=http://127.0.0.1:3000/mcp \
  -e "WAZUH_MCP_API_KEY=$WAZUH_API_KEY" -- \
  "$ASSISTANT_DIR/venv/bin/python" "$ASSISTANT_DIR/wazuh_http_bridge.py"
unset WAZUH_API_KEY
```

If you changed the Wazuh MCP port or installed the service on another host, change `WAZUH_MCP_URL`. Remote connections must use HTTPS through a trusted TLS proxy. Do not set `WAZUH_MCP_URL` to the unauthenticated HTTP port on a network interface.

## 5. Register the Shodan MCP server

The Shodan integration uses the community [Shodan MCP server project](https://github.com/w0h1v/mcp-shodan), published to npm as `@burtthecoder/mcp-shodan`. This build pins version `1.0.37` in the dependency lock; it does not clone or copy that project's source into this repository. The upstream project is MIT licensed; see its [license](https://github.com/w0h1v/mcp-shodan/blob/main/LICENSE). You need your own Shodan API key, and Shodan receives the public lookups you make.

Enter the key without echoing it in the terminal. Claude Code stores MCP server configuration in your local user configuration, including this environment value, so protect your local account and configuration files:

If you are upgrading from the earlier Shodan MCP entry, remove it first:

```bash
claude mcp remove shodan
```

```bash
read -rsp 'Shodan API key: ' SHODAN_KEY; echo
claude mcp add --scope user --transport stdio shodan \
  -e "SHODAN_API_KEY=$SHODAN_KEY" -- \
  "$ASSISTANT_DIR/venv/bin/python" "$ASSISTANT_DIR/privacy_proxy.py" shodan \
  npx -y @burtthecoder/mcp-shodan@1.0.37
unset SHODAN_KEY
```

The Shodan key is supplied at the hidden prompt; it should not appear in the command itself or in Git. The privacy proxy blocks private and placeholder lookups before they reach Shodan.

## 6. Check MCP registration

```bash
claude mcp list
```

Confirm that both `wazuh` and `shodan` appear and are connected before starting the web app. The local Wazuh MCP server process must be running whenever you use the assistant. If you later move the assistant checkout, remove and re-add its MCP entries because their commands contain absolute paths.

## 7. Start the assistant

Start Flask using the same terminal where you installed/authenticated Claude Code. If you authenticated by signing in through Claude Code, run:

```bash
cd "$ASSISTANT_DIR"
source venv/bin/activate
python app.py
```

If you use API-key authentication instead of the Claude Code sign-in, enter and export the key in that terminal before starting the app:

```bash
read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY; echo
export ANTHROPIC_API_KEY
cd "$ASSISTANT_DIR"
source venv/bin/activate
python app.py
```

Open <http://127.0.0.1:8080> in a browser on the same machine. Keep the app bound to `127.0.0.1`; this single-user UI has no login. Stop it with `Ctrl+C`. For a persistent local service, adapt [`deploy/soc-assistant.service.example`](deploy/soc-assistant.service.example) to your paths and user.

## Scope and operating notes

- The interface is for one local analyst at a time. Do not expose it to a network.
- The app allows Wazuh and Shodan MCP tools and blocks shell, file-editing, and web tools in its Claude Code invocation.
- Use read-only Wazuh credentials. Server-side Wazuh permissions are the access control.
- The assistant provides triage assistance. Verify findings in Wazuh; response actions are outside this demo's scope.
- Machine-wide Claude Code restrictions and the optional prompt-guard hook are not installed by this repository.
- Local chat history and pseudonym mappings are retained for up to seven days.

## Local data and secrets

The app creates `history.db`, `pseudo.db`, and `audit.log` beside `app.py`. They may contain conversation text, pseudonym mappings, and tool-call metadata. Keep them local and protected; `.gitignore` excludes these files, the local privacy config, credentials, and virtual environments. Do not commit API keys, passwords, `.env` files, or local Claude configuration.

## Repository contents

- `app.py`, `static/index.html`: Flask chat application and browser UI.
- `privacy.py`, `privacy_plus.py`: masking, response scrubbing, and privacy rules.
- `privacy_proxy.py`: stdio privacy proxy for Shodan MCP traffic.
- `wazuh_http_bridge.py`: local stdio-to-Streamable-HTTP bridge; detokenizes Wazuh requests and scrubs responses.
- `privacy_notes.py`: privacy-filter summary appended to answers.
- `privacy_config.example.json`: safe starter configuration; copy it to the ignored local `privacy_config.json` and customize it.
- `integrations/`: pinned MCP dependency metadata and a credential-free Wazuh MCP environment template.
- `test_privacy.py`: privacy-layer self-check supplied with this build.
- `test_wazuh_http_bridge.py`: local protocol check for bridge authentication, identifier restoration, and response scrubbing.
- `deploy/`: local service-unit example.

## License and third-party credit

This project is licensed under Apache-2.0; see [LICENSE](LICENSE). Third-party components remain under their own licenses. This build uses the [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) and [Shodan MCP server](https://github.com/w0h1v/mcp-shodan); please see their upstream repositories for their source, licenses, and updates.
