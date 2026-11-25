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
| Browser | A modern browser. For a remote VM, use a browser on your workstation through an SSH tunnel. |

The app, local bridge, and source-installed Wazuh MCP server need Python 3.11 or newer. This setup also needs the current Node.js LTS release with npm/npx, Git, the latest Claude Code CLI, and an Anthropic API key. You also need a Wazuh deployment with read-only Manager API and Indexer accounts, and a Shodan API key. The Wazuh MCP Server 5.0 line supports Wazuh 4.8 through 4.14.7. See [Anthropic's Claude Code system requirements](https://docs.anthropic.com/en/docs/claude-code/getting-started) for its documented OS, memory, software, and network requirements.

Ensure the Assistant VM can reach the Wazuh Manager API on port `55000` and the Indexer on port `9200`. Permit only the required component-to-component connections through the network firewalls: the Assistant VM to the Manager and Indexer, the Dashboard VM to the Manager API and Indexer, and the Manager/Filebeat to the Indexer as required by your deployment. Restrict these ports to the source VMs that need them. The MCP endpoint and Flask UI stay on loopback; do not expose ports `3000` or `8080` to the network.

### Distributed Wazuh addresses

In a distributed Wazuh installation, configure each component with the reachable address of the VM running the service it needs. `localhost` and `127.0.0.1` always mean the current VM. Use private IP addresses or internal DNS names between VMs, and make sure the target service is listening on that address.

| Connection | Setting or file | Address to use |
| --- | --- | --- |
| Assistant → Manager API | Assistant MCP `.env`: `WAZUH_HOST` | Manager VM's reachable IP or DNS name; port `55000`. |
| Assistant → Indexer | Assistant MCP `.env`: `WAZUH_INDEXER_HOST` | Indexer VM's reachable IP or DNS name; port `9200`. |
| Dashboard → Indexer | `/etc/wazuh-dashboard/opensearch_dashboards.yml`: `opensearch.hosts` | Indexer address that is listening for the Dashboard. Set `https://INDEXER_IP:9200` when the Indexer does not listen on loopback, even if Dashboard and Indexer share a VM. |
| Dashboard → Manager API | `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml`: the `url` under the `default` API host | Manager VM's reachable IP or DNS name; port `55000`, when the Manager is on another VM. |

For example, if Dashboard and Indexer share a VM but the Indexer listens only on `172.31.46.1:9200`, the Dashboard setting must use `https://172.31.46.1:9200`; `https://127.0.0.1:9200` will fail. If the Manager is separate, its address in the Dashboard API configuration must point to the Manager VM, not the Dashboard VM. Keep the Assistant's and Dashboard's addresses consistent with the actual service listeners. Do not change a service's bind address to loopback just to match a client configuration if other VMs also need to reach it.

For an **all-in-one installation** where the Assistant, Manager, Indexer, and Dashboard are on one machine, `localhost` is suitable for a service only when that service listens on loopback. For example, `WAZUH_HOST=127.0.0.1` and `WAZUH_INDEXER_HOST=127.0.0.1` work only if the Manager API and Indexer accept connections there. The Dashboard's `opensearch.hosts` can use `https://127.0.0.1:9200` only if the Indexer listens on loopback. If a service listens only on the machine's private IP, use that IP even though everything is on one machine. The services normally use different ports (`55000` for the Manager API, `9200` for the Indexer, `3000` for the local MCP, and `8080` for the Assistant UI), so port conflicts are separate from whether `localhost` reaches a service. Avoid running another process on the same address and port.

## Before you start

Run the steps in order on the SOC Assistant VM, except where a section says to use a Wazuh host or your workstation. Keep the setup shell open while using its exported path variables. Before using the assistant, customize only the items listed here:

Complete Steps 1–8 in order. The MCP registration steps add the Wazuh privacy bridge and Shodan proxy to Claude Code so the assistant can use both integrations.

| File or prompt | What you must supply |
| --- | --- |
| `privacy_config.json` | Optional. You can leave the built-in privacy defaults in place and add organization-specific ranges or terms later. |
| Wazuh MCP `.env` | Reachable Wazuh Manager and Indexer addresses, credentials for the separate read-only Manager API and Indexer accounts, and TLS settings that match your certificates. |
| Wazuh MCP API key | Generated read-only key; the local bridge uses it to obtain a short-lived bearer token. |
| Wazuh MCP source checkout | The project maintainer's fork, installed in its own Python virtual environment and configured with your Wazuh endpoints. |
| Shodan prompt | Your Shodan API key. |
| Anthropic API key | An API key created in the [Anthropic Console](https://console.anthropic.com/). Step 8 stores it once in a permission-protected config file outside the repository. |
| Path variables in Step 1 | Change them only if you choose a different directory from the defaults. |

Do not leave angle-bracket examples such as `<READ_ONLY_MANAGER_API_USER>` or `<READ_ONLY_INDEXER_USER>` in place. Replace them with real values before starting the MCP server. Keep API keys and passwords out of committed files and shell command text.

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

Create an Anthropic API key in the [Anthropic Console](https://console.anthropic.com/). This setup uses API-key authentication for every replica; do not run `claude` to sign in with a Claude account. Step 8 securely prompts for the key once and stores it in a permission-protected config file outside the repository, where the app service reads it on every start. Do not put the key in a command or commit it to this repository. See [Anthropic's Claude Code setup guide](https://docs.anthropic.com/en/docs/claude-code/getting-started) for API-key configuration details.

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

Python, Git, Node.js LTS, and Claude Code are installed from current supported releases. The Wazuh MCP integration clones the project maintainer's fork, [`efamharris/Wazuh-MCP-Server`](https://github.com/efamharris/Wazuh-MCP-Server), on its `main` branch. That fork does not automatically receive later changes from the original GenSecAI project, so the assistant setup is insulated from upstream changes until the project maintainer reviews and merges them. Shodan MCP `1.0.37` and the MCP Python SDK `2.3.0` are recorded in [`integrations/wazuh-mcp-server.lock`](integrations/wazuh-mcp-server.lock) and `requirements.txt`.

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
export WAZUH_MCP_DIR="$HOME/Wazuh-MCP-Server"
```

If you cloned either repository to another location, change the matching path above before continuing. All later commands use these variables, so keep them set in this terminal.

## 2. Install the assistant

```bash
cd "$ASSISTANT_DIR"
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Optional: add organization-specific privacy terms

You do **not** need to create or edit `privacy_config.json` to install or start the assistant. If the file is absent, the app uses its built-in behavior: it pseudonymizes non-public IP addresses and email addresses, pseudonymizes host and username values found in recognized Wazuh fields, and redacts common secret formats and secret-valued fields. You can proceed directly to Step 3 and tailor this file later.

Use this optional file to add public IP ranges that belong to your organization and names or terms specific to your organization that you want pseudonymized before prompts or Wazuh results reach Claude. These entries extend the built-in behavior; they do not replace it. Leave an array empty if you have nothing to add.

If you want to configure those extra terms now, copy the example and restrict its permissions:

```bash
cp "$ASSISTANT_DIR/privacy_config.example.json" "$ASSISTANT_DIR/privacy_config.json"
chmod 600 "$ASSISTANT_DIR/privacy_config.json"
nano "$ASSISTANT_DIR/privacy_config.json"
```

Add only the ranges and terms you want treated as organization-specific. Enter IP ranges in CIDR notation (for example, `198.51.100.10/32` is documentation-only; replace it with a real range you own). Enter terms as JSON strings in double quotes, separated by commas. The example starts with both arrays empty, which is valid. Save and exit (`Ctrl+O`, `Enter`, `Ctrl+X` in nano). You can edit this file later; restart the assistant and its Claude Code session after changes so they reload it. Do not commit `privacy_config.json`.

## 3. Install the Wazuh MCP server from the project maintainer's fork

This guide installs the community [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) through the project maintainer's fork, [`efamharris/Wazuh-MCP-Server`](https://github.com/efamharris/Wazuh-MCP-Server). The fork gives the project a controlled source for replication while upstream changes are reviewed and compatibility-tested. It does not claim authorship; see [Third-party credit](#license-and-third-party-credit) for attribution. The commands below clone the fork's `main` branch. **Do not substitute the original `gensecaihq/Wazuh-MCP-Server` URL, a `5.0.0`/`v5.0.0` release tag, or `git describe --tags`; those would bypass the maintained fork branch.** The server exposes Streamable HTTP. The local [`wazuh_http_bridge.py`](wazuh_http_bridge.py) connects to it, detokenizes Wazuh queries, and scrubs returned data before Claude receives it. The bridge was verified against upstream `v5.0.0` and the maintained fork's `main` at commit `e751871`. The live Manager and Indexer connection still needs to pass the checks in this guide before operational use.

Clone the maintained fork, create its own virtual environment, and install the MCP server package. These are the source checkout commands for a fresh replication:

```bash
export ASSISTANT_DIR="${ASSISTANT_DIR:-$HOME/wazuh-soc-assistant}"
export WAZUH_MCP_DIR="${WAZUH_MCP_DIR:-$HOME/Wazuh-MCP-Server}"
cd "$HOME"
git clone --branch main https://github.com/efamharris/Wazuh-MCP-Server.git "$WAZUH_MCP_DIR"
cd "$WAZUH_MCP_DIR"
pwd
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
cp "$ASSISTANT_DIR/integrations/wazuh-mcp-server.env.example" .env
chmod 600 .env
```

The project maintainer evaluates upstream changes in a separate branch, reviews them, and tests compatibility with the bridge and a Wazuh deployment before merging approved changes into the maintained fork's `main`. A replica uses the maintained fork as it exists when cloned. New upstream changes do not appear there automatically; a new replica receives them only after the project maintainer updates the fork.

### Prepare the two Wazuh read-only accounts

The MCP server connects to two separate Wazuh services, so its `.env` needs valid credentials for both. They are separate accounts in separate authentication systems. Create them with the copy-and-run commands below, or follow the equivalent dashboard steps. Do not use an administrator account for normal assistant access.

1. **Manager API account (`WAZUH_USER` / `WAZUH_PASS`):** create a Wazuh Server API user and assign the built-in `readonly` role. On a standard Wazuh installation this built-in role has role ID `2`; the command below looks up the role ID instead of assuming it. This grants read-only Manager API access for agent and system tools. See Wazuh's [API RBAC documentation](https://documentation.wazuh.com/current/user-manual/api/rbac/configuration.html).
2. **Indexer account (`WAZUH_INDEXER_USER` / `WAZUH_INDEXER_PASS`):** create an Indexer internal user and map it to a custom read-only Indexer role with cluster permission `cluster:monitor/health` and index permission `read` for `wazuh-alerts-*` and `wazuh-states-vulnerabilities-*`. The health permission is needed for `/ready`; the index permissions support alert and vulnerability queries. Do not grant write permissions. See the Wazuh MCP [Indexer access requirements](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/docs/security/README.md).

Use the following commands from a Bash terminal that can reach the Wazuh Manager API. Before running the block, replace `MANAGER_IP` with the Manager VM's reachable IP address (for example, its private IP) or DNS name. Do not leave it as `MANAGER_IP`; `localhost` is correct only when the command runs on the Manager VM itself. The commands use the Wazuh Manager API administrator account `wazuh` by default. The first password prompt explicitly asks for the **Wazuh Manager API admin password** for that account. It is not the Indexer `admin` password and not the new read-only user's password. The admin password is kept out of shell history and curl's command-line arguments. `curl -k` skips certificate verification and is included for the default self-signed Wazuh certificate; remove `-k` or use `--cacert /path/to/CA.pem` when you have a trusted CA certificate.

For an installation created with Wazuh's assisted installer, the `wazuh` API password is in its generated `wazuh-install-files.tar` archive. On the machine where that archive is stored, run the command below and use the password shown for the `wazuh` API user at the prompt in the next block. Replace the archive path if yours is elsewhere. This displays a secret in your terminal; do not share or paste its output.

```bash
sudo tar -xOf /path/to/wazuh-install-files.tar \
  wazuh-install-files/wazuh-passwords.txt \
  | grep -P "'wazuh'" -A 1
```

Choose a unique username and a password for the new read-only account before running the command. Wazuh requires API user passwords to be 8–64 characters and include uppercase and lowercase letters, a number, and a symbol. Record the password securely for the MCP `.env` file; avoid whitespace to make `.env` entry straightforward.

```bash
(
set -e
WAZUH_MANAGER_HOST='MANAGER_IP' # CHANGE this placeholder to the Manager's reachable IP address or DNS name.
if [[ "$WAZUH_MANAGER_HOST" == 'MANAGER_IP' ]]; then
  echo 'Edit WAZUH_MANAGER_HOST and replace MANAGER_IP with the Manager address before running this block.' >&2
  exit 1
fi
WAZUH_API_BASE="https://${WAZUH_MANAGER_HOST}:55000"
read -rp 'Wazuh API admin username [wazuh]: ' WAZUH_API_ADMIN
WAZUH_API_ADMIN="${WAZUH_API_ADMIN:-wazuh}"
read -rsp "Wazuh Manager API admin password (for user ${WAZUH_API_ADMIN}): " WAZUH_API_ADMIN_PASS; echo
read -rp 'New read-only Manager API username: ' MANAGER_RO_USER
read -rsp 'New read-only Manager API password: ' MANAGER_RO_PASS; echo

WAZUH_ADMIN_CURL_CONFIG="$(mktemp)"
chmod 600 "$WAZUH_ADMIN_CURL_CONFIG"
trap 'rm -f "$WAZUH_ADMIN_CURL_CONFIG"' EXIT
WAZUH_ADMIN_CURL_USER="$(WAZUH_API_ADMIN="$WAZUH_API_ADMIN" WAZUH_API_ADMIN_PASS="$WAZUH_API_ADMIN_PASS" \
  python3 -c 'import json,os; print(json.dumps(os.environ["WAZUH_API_ADMIN"]+":"+os.environ["WAZUH_API_ADMIN_PASS"]))')"
printf 'user = %s\n' "$WAZUH_ADMIN_CURL_USER" > "$WAZUH_ADMIN_CURL_CONFIG"
unset WAZUH_ADMIN_CURL_USER WAZUH_API_ADMIN_PASS
WAZUH_API_TOKEN="$(curl --config "$WAZUH_ADMIN_CURL_CONFIG" -skS --fail-with-body -X POST \
  "$WAZUH_API_BASE/security/user/authenticate?raw=true")"
rm -f "$WAZUH_ADMIN_CURL_CONFIG"
trap - EXIT
MANAGER_ROLE_ID="$(curl -skS --fail-with-body -H "Authorization: Bearer $WAZUH_API_TOKEN" \
  "$WAZUH_API_BASE/security/roles?search=readonly" \
  | python3 -c 'import json,sys; roles=json.load(sys.stdin)["data"]["affected_items"]; print(next(str(r["id"]) for r in roles if r["name"].lower()=="readonly"))')"
MANAGER_USER_JSON="$(MANAGER_RO_USER="$MANAGER_RO_USER" MANAGER_RO_PASS="$MANAGER_RO_PASS" \
  python3 -c 'import json,os; print(json.dumps({"username":os.environ["MANAGER_RO_USER"],"password":os.environ["MANAGER_RO_PASS"]}))')"
MANAGER_USER_RESPONSE="$(printf '%s' "$MANAGER_USER_JSON" \
  | curl -skS --fail-with-body -H "Authorization: Bearer $WAZUH_API_TOKEN" \
      -H 'Content-Type: application/json' -X POST \
      --data-binary @- "$WAZUH_API_BASE/security/users")"
MANAGER_USER_ID="$(printf '%s' "$MANAGER_USER_RESPONSE" \
  | python3 -c '
import json,sys
response=json.load(sys.stdin)
data=response.get("data") or {}
items=data.get("affected_items") or []
if not items or not items[0].get("id"):
    print("Wazuh did not create the user. API response details:", file=sys.stderr)
    print(json.dumps({"message":response.get("message"),"failed_items":data.get("failed_items")}, indent=2), file=sys.stderr)
    sys.exit(1)
print(items[0]["id"])
')"
curl -skS --fail-with-body -H "Authorization: Bearer $WAZUH_API_TOKEN" -X POST \
  "$WAZUH_API_BASE/security/users/$MANAGER_USER_ID/roles?role_ids=$MANAGER_ROLE_ID"
echo "When curl prompts next, enter the new read-only Manager API password for user ${MANAGER_RO_USER}."
MANAGER_RO_TOKEN="$(curl -skS --fail-with-body -u "$MANAGER_RO_USER" -X POST \
  "$WAZUH_API_BASE/security/user/authenticate?raw=true")"
curl -skS --fail-with-body -o /dev/null -w 'Manager read check: HTTP %{http_code}\n' \
  -H "Authorization: Bearer $MANAGER_RO_TOKEN" "$WAZUH_API_BASE/agents?limit=1"
unset WAZUH_API_TOKEN MANAGER_RO_TOKEN MANAGER_RO_PASS MANAGER_USER_JSON MANAGER_USER_RESPONSE
)
```

The first `curl -u` call prompts for the **Wazuh Manager API admin password** for the admin username entered above (default `wazuh`). The script looks up the `readonly` role ID rather than assuming it is `2`, creates the user, assigns that role, then authenticates as the new user and verifies an agent read returns HTTP 200. Record the new username and password in a password manager for the MCP `.env` file; the script does not print the password. This is a one-time administrator operation; do not put the admin password in `.env`. If that username already exists, do not rerun the `POST` create command; verify the existing account's role and use its existing credentials.

Create the Indexer internal user and its read-only role with the Security REST API. Run these commands from a terminal that can reach the Indexer. Before running the block, replace `INDEXER_IP` with the Indexer's reachable IP address (for example, its private IP) or DNS name. Do not leave it as `INDEXER_IP`; `localhost` is correct only when the command runs on the Indexer VM itself. Choose and record a strong new read-only user's password before running this block; avoid whitespace so it is easy to enter in `.env`. The block prompts once for the **Wazuh Indexer admin password for the `admin` account**, then reuses it securely for the three setup requests. This is not the Wazuh Manager API admin password or the new read-only user's password. As above, `-k` is for a default self-signed certificate; use certificate verification for a trusted CA.

```bash
(
set -e
INDEXER_HOST='INDEXER_IP' # CHANGE this placeholder to the Indexer's reachable IP address or DNS name.
if [[ "$INDEXER_HOST" == 'INDEXER_IP' ]]; then
  echo 'Edit INDEXER_HOST and replace INDEXER_IP with the Indexer address before running this block.' >&2
  exit 1
fi
read -rp 'New read-only Indexer username [soc_assistant_ro]: ' INDEXER_RO_USER
INDEXER_RO_USER="${INDEXER_RO_USER:-soc_assistant_ro}"
read -rsp 'New read-only Indexer password: ' INDEXER_RO_PASS; echo
read -rsp 'Wazuh Indexer admin password (for user admin): ' INDEXER_ADMIN_PASS; echo
INDEXER_SECURITY_API="https://${INDEXER_HOST}:9200/_plugins/_security/api"
INDEXER_USER_JSON="$(INDEXER_RO_USER="$INDEXER_RO_USER" INDEXER_RO_PASS="$INDEXER_RO_PASS" \
  python3 -c 'import json,os; print(json.dumps({"password":os.environ["INDEXER_RO_PASS"],"backend_roles":[],"attributes":{}}))')"
INDEXER_MAPPING_JSON="$(INDEXER_RO_USER="$INDEXER_RO_USER" \
  python3 -c 'import json,os; print(json.dumps({"users":[os.environ["INDEXER_RO_USER"]],"backend_roles":[],"hosts":[]}))')"
INDEXER_CURL_CONFIG="$(mktemp)"
chmod 600 "$INDEXER_CURL_CONFIG"
trap 'rm -f "$INDEXER_CURL_CONFIG"' EXIT
INDEXER_CURL_USER="$(INDEXER_ADMIN_PASS="$INDEXER_ADMIN_PASS" \
  python3 -c 'import json,os; print(json.dumps("admin:"+os.environ["INDEXER_ADMIN_PASS"]))')"
printf 'user = %s\n' "$INDEXER_CURL_USER" > "$INDEXER_CURL_CONFIG"
unset INDEXER_CURL_USER INDEXER_ADMIN_PASS

indexer_security_put() {
  local endpoint="$1" body="$2" body_file result
  body_file="$(mktemp)"
  chmod 600 "$body_file"
  printf '%s' "$body" > "$body_file"
  if curl --config "$INDEXER_CURL_CONFIG" -skS --fail-with-body -H 'Content-Type: application/json' -X PUT \
    --data-binary "@$body_file" "$INDEXER_SECURITY_API/$endpoint"
  then result=0; else result=$?; fi
  rm -f "$body_file"
  return "$result"
}

indexer_security_put "internalusers/$INDEXER_RO_USER" "$INDEXER_USER_JSON"
indexer_security_put "roles/soc_assistant_readonly" \
  '{"cluster_permissions":["cluster:monitor/health"],"index_permissions":[{"index_patterns":["wazuh-alerts-*","wazuh-states-vulnerabilities-*"],"allowed_actions":["read"]}],"tenant_permissions":[]}'
indexer_security_put "rolesmapping/soc_assistant_readonly" "$INDEXER_MAPPING_JSON"
INDEXER_CURL_USER="$(INDEXER_RO_USER="$INDEXER_RO_USER" INDEXER_RO_PASS="$INDEXER_RO_PASS" \
  python3 -c 'import json,os; print(json.dumps(os.environ["INDEXER_RO_USER"]+":"+os.environ["INDEXER_RO_PASS"]))')"
printf 'user = %s\n' "$INDEXER_CURL_USER" > "$INDEXER_CURL_CONFIG"
unset INDEXER_CURL_USER INDEXER_RO_PASS
curl --config "$INDEXER_CURL_CONFIG" -skS --fail-with-body -o /dev/null \
  -w 'Indexer cluster-health check: HTTP %{http_code}\n' \
  "https://${INDEXER_HOST}:9200/_cluster/health"
rm -f "$INDEXER_CURL_CONFIG"
trap - EXIT
unset INDEXER_USER_JSON INDEXER_MAPPING_JSON
)
```

The block prompts once for each password: first the new read-only Indexer password, then the **Wazuh Indexer admin password for account `admin`**. It creates the internal user, the read-only role, and the role mapping, then authenticates as the new user to confirm its cluster-health permission returns HTTP 200. The Indexer role grants only cluster health checks and read access to the alert and vulnerability indices used by this setup; it grants no write permission. The role and mapping names can be changed, but use the same role name in both API requests. See the [OpenSearch Security REST API](https://docs.opensearch.org/latest/security/api/index/) for these endpoints and the Wazuh [RBAC documentation](https://documentation.wazuh.com/current/user-manual/api/rbac/configuration.html) for Manager users and role assignment.

After creating both accounts, store only their dedicated read-only usernames and passwords in the MCP `.env`. Do not place administrator credentials there. The Indexer account does not need write access.

Edit the environment file:

```bash
nano "$WAZUH_MCP_DIR/.env"
```

Replace `WAZUH_HOST`, `WAZUH_USER`, and `WAZUH_PASS` with the reachable Manager address and the dedicated API user assigned the built-in `readonly` role. Replace `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, and `WAZUH_INDEXER_PASS` with the Indexer address and the dedicated internal user mapped to the role described above. If a password contains whitespace or `#`, quote it in the `.env` value. If the Indexer returns HTTP 403 for `cluster:monitor/health`, add that exact permission to its mapped role; for 403 on index searches, confirm `read` access to both specified index patterns. Change ports only if your Wazuh services use non-default ports. The example uses strict TLS verification; if your certificates are private, set `WAZUH_CA_BUNDLE` to the CA bundle's path on this VM. For a stock self-signed Manager certificate, set `WAZUH_ALLOW_SELF_SIGNED=true`; set `WAZUH_INDEXER_VERIFY_SSL=false` only if you deliberately accept the Indexer's certificate without verification. Do not leave angle-bracket placeholders. Save and exit nano.

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

Run the Wazuh MCP server as a systemd service so it stays in the background and starts automatically after a VM reboot. The service launcher loads the maintained fork's `.env` file using its own virtual environment. If you already started it in a foreground terminal, stop that process with `Ctrl+C`. If you started it with the earlier background command, stop that process and remove its old PID file before starting the service:

```bash
if [ -f "$HOME/.local/run/wazuh-mcp-server.pid" ]; then
  OLD_MCP_PID="$(cat "$HOME/.local/run/wazuh-mcp-server.pid")"
  if ps -p "$OLD_MCP_PID" -o args= 2>/dev/null | grep -q '[w]azuh_mcp_server'; then
    kill "$OLD_MCP_PID"
  fi
  rm "$HOME/.local/run/wazuh-mcp-server.pid"
  unset OLD_MCP_PID
fi
```

Install and start the service only after completing Step 3, including creating the Wazuh MCP checkout's `.venv` and `.env`. The service template and launcher are supplied by this SOC Assistant repository under `$ASSISTANT_DIR/deploy`; they are not files from the Wazuh MCP fork. If cloning the Assistant from GitHub, use a commit that includes both files. These commands fill in the Linux username in the service template; if either checkout is in a non-default directory, edit the template paths before installing it. They check that both service files exist, so an older Assistant checkout stops with a clear message instead of writing an empty unit:

```bash
if [ -f "$ASSISTANT_DIR/deploy/wazuh-mcp-server.service.example" ] \
  && [ -f "$ASSISTANT_DIR/deploy/run_wazuh_mcp_server.py" ] \
  && [ -x "$WAZUH_MCP_DIR/.venv/bin/python" ] && [ -s "$WAZUH_MCP_DIR/.env" ]; then
  sudo sed "s|<YOUR_LINUX_USER>|$(id -un)|g" "$ASSISTANT_DIR/deploy/wazuh-mcp-server.service.example" \
    | sudo tee /etc/systemd/system/wazuh-mcp-server.service > /dev/null
  sudo grep -nE '^(User|WorkingDirectory|Environment|ExecStart)=' /etc/systemd/system/wazuh-mcp-server.service
  if sudo grep -q '<YOUR_LINUX_USER>' /etc/systemd/system/wazuh-mcp-server.service; then
    echo 'Username placeholder remains in the service file; correct the template before starting it.'
  else
    sudo systemctl unmask wazuh-mcp-server
    sudo systemctl daemon-reload
    sudo systemctl enable --now wazuh-mcp-server
    sudo systemctl status wazuh-mcp-server --no-pager
  fi
else
  echo 'Prerequisite missing: the Assistant deploy service files must exist under ASSISTANT_DIR/deploy, and Step 3 must have created WAZUH_MCP_DIR/.venv/bin/python and WAZUH_MCP_DIR/.env. Check that this is the current Assistant checkout and that Step 3 completed before continuing.'
fi
```

Check that the printed service settings show the real username and paths, with no `<YOUR_LINUX_USER>` placeholder left. For server logs, use `sudo journalctl -u wazuh-mcp-server -n 50 --no-pager`.

Check readiness from the same VM terminal:

```bash
export ASSISTANT_DIR="$HOME/wazuh-soc-assistant"
export WAZUH_MCP_DIR="$HOME/Wazuh-MCP-Server"
curl -sS -i http://127.0.0.1:3000/ready
```

The server listens on loopback port `3000`; leave it local. `/ready` checks the MCP process, Wazuh Manager, configured Indexer, and VM memory. It can return `503` while the process is running if one of those readiness checks fails. The command above shows the status and diagnostic JSON even on `503`. Check `services.wazuh_manager`, `services.wazuh_manager_reason`, `services.wazuh_indexer`, and `services.memory` in the response body. `wazuh_manager_reason` reports a general category such as `unreachable`, `authentication_failed`, or `tls_verification_failed`. For detailed server errors, inspect the service log with `sudo journalctl -u wazuh-mcp-server -n 50 --no-pager`. Correct the indicated host, credentials, TLS settings, network route, or VM memory issue, then retry `/ready` before continuing. `/health` only confirms that the service process is responding; it does not confirm Wazuh connectivity.

The MCP server permits read-only tools through the `wazuh:read` key scope and exposes only the `alerts`, `agents`, `vulnerabilities`, `analysis`, `compliance`, and `system` toolsets. The `response` and `web_search` toolsets are not enabled.

## 4. Register the Wazuh privacy bridge

The `claude mcp add` command below registers the local privacy bridge with Claude Code. Claude Code launches it when needed to access Wazuh through this assistant's privacy filtering. It is not a separate server process you need to start. Claude Code stores the MCP API key in its local MCP configuration, so protect your local account and configuration files.

```bash
WAZUH_API_KEY="$(sed -n 's/^MCP_API_KEY=//p' "$WAZUH_MCP_DIR/.env")"
if [ -n "$WAZUH_API_KEY" ]; then
  claude mcp add --scope user --transport stdio wazuh \
    -e WAZUH_MCP_URL=http://127.0.0.1:3000/mcp \
    -e "WAZUH_MCP_API_KEY=$WAZUH_API_KEY" -- \
    "$ASSISTANT_DIR/venv/bin/python" "$ASSISTANT_DIR/wazuh_http_bridge.py"
else
  echo 'MCP_API_KEY is missing from the Wazuh MCP .env. Generate it in Step 3 before registering the bridge.'
fi
unset WAZUH_API_KEY
```

If you changed the Wazuh MCP port or installed the service on another host, change `WAZUH_MCP_URL`. Remote connections must use HTTPS through a trusted TLS proxy. Do not set `WAZUH_MCP_URL` to the unauthenticated HTTP port on a network interface.

## 5. Register the Shodan MCP server

The Shodan integration uses the community [Shodan MCP server project](https://github.com/w0h1v/mcp-shodan), published to npm as `@burtthecoder/mcp-shodan`. This build pins version `1.0.37` in the dependency lock; it does not clone or copy that project's source into this repository. The upstream project is MIT licensed; see its [license](https://github.com/w0h1v/mcp-shodan/blob/main/LICENSE). You need your own Shodan API key, and Shodan receives the public lookups you make.

Enter the key without echoing it in the terminal. Claude Code stores MCP server configuration in your local user configuration, including this environment value, so protect your local account and configuration files:

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

## 7. Run the local verification checks

Run these basic checks in the assistant checkout with its virtual environment active. They check Python syntax and the built-in privacy behavior without requiring separate test files:

```bash
export ASSISTANT_DIR="$HOME/wazuh-soc-assistant"
cd "$ASSISTANT_DIR"
source venv/bin/activate
python -m py_compile app.py privacy.py privacy_notes.py privacy_proxy.py wazuh_http_bridge.py deploy/run_wazuh_mcp_server.py
python test_privacy.py
```

Continue to the live readiness check and Wazuh query below to verify the integration with your deployment.

## 8. Start the assistant and test a live query

The Flask app and Wazuh MCP server both run as systemd services on the VM, in the background and automatically after reboot. The Flask service is ordered after and requires the Wazuh MCP service. It reads the Anthropic API key from a protected file, so you do not enter or export it each time. The app does not open a browser window. Create an SSH tunnel from your workstation to use the browser; only the workstation tunnel needs a terminal left open.

### On the VM: start the app

On the VM, set the assistant path, then create the protected service config file. The API key is prompted without echo. The config also records the Claude CLI path and the Node.js `npx` directory because systemd does not inherit the interactive shell's PATH; Claude Code needs `npx` to launch the Shodan MCP. These values are stored outside the Git checkout. Do this once, or again if you rotate the key or change your Node.js/Claude installation:

```bash
export ASSISTANT_DIR="$HOME/wazuh-soc-assistant"
install -d -m 700 "$HOME/.config/soc-assistant"
umask 077
read -rsp 'Anthropic API key: ' ANTHROPIC_API_KEY; echo
CLAUDE_BIN_PATH="$(command -v claude || true)"
NPX_BIN_PATH="$(command -v npx || true)"
NODE_BIN_DIR="$(dirname "$NPX_BIN_PATH")"
if [ -x "$CLAUDE_BIN_PATH" ] && [ -x "$NPX_BIN_PATH" ]; then
  printf 'ANTHROPIC_API_KEY=%s\nCLAUDE_BIN=%s\nPATH=%s:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' \
    "$ANTHROPIC_API_KEY" "$CLAUDE_BIN_PATH" "$NODE_BIN_DIR" > "$HOME/.config/soc-assistant/env"
  chmod 600 "$HOME/.config/soc-assistant/env"
  echo "Saved the protected app config. Claude: $CLAUDE_BIN_PATH; npx: $NPX_BIN_PATH"
else
  echo 'Claude Code or npx was not found. Fix the Node.js/Claude installation and PATH, then rerun this key-save step.'
fi
unset ANTHROPIC_API_KEY
unset CLAUDE_BIN_PATH NPX_BIN_PATH NODE_BIN_DIR
```

Install and start the systemd service. These commands fill in the Linux username in the provided service template, then enable the app to start automatically after a VM reboot. If the assistant checkout is not at `~/wazuh-soc-assistant`, edit `WorkingDirectory` and `ExecStart` in the template to use the actual `$ASSISTANT_DIR` path before installing it:

```bash
if [ -f "$ASSISTANT_DIR/deploy/soc-assistant.service.example" ] \
  && [ -x "$ASSISTANT_DIR/venv/bin/python" ] \
  && grep -q '^ANTHROPIC_API_KEY=.' "$HOME/.config/soc-assistant/env" \
  && grep -q '^CLAUDE_BIN=/' "$HOME/.config/soc-assistant/env" \
  && grep -q '^PATH=/' "$HOME/.config/soc-assistant/env"; then
  sudo sed "s|<YOUR_LINUX_USER>|$(id -un)|g" "$ASSISTANT_DIR/deploy/soc-assistant.service.example" \
    | sudo tee /etc/systemd/system/soc-assistant.service > /dev/null
  sudo grep -nE '^(User|WorkingDirectory|EnvironmentFile|ExecStart)=' /etc/systemd/system/soc-assistant.service
  if sudo grep -q '<YOUR_LINUX_USER>' /etc/systemd/system/soc-assistant.service; then
    echo 'Username placeholder remains in the service file; correct the template before starting it.'
  else
    sudo systemctl unmask soc-assistant
    sudo systemctl daemon-reload
    sudo systemctl enable --now soc-assistant
    sudo systemctl status soc-assistant --no-pager
  fi
else
  echo 'Required app service template, virtual environment, or protected API/CLI configuration is missing. Finish Steps 1, 2, and the key-save commands before continuing.'
fi
```

The `sed` expression must replace the template's literal `<YOUR_LINUX_USER>` placeholder. Check the printed service settings: they should contain the actual Linux username and paths, with no `<YOUR_LINUX_USER>` text remaining.

Check both services and their endpoints on the VM:

```bash
sudo systemctl status soc-assistant wazuh-mcp-server --no-pager
curl -sS -i http://127.0.0.1:3000/ready
curl -sS -I http://127.0.0.1:8080
```

The UI should return HTTP 200, and `/ready` should return HTTP 200 with `"status":"healthy"`. If either check fails, inspect `sudo journalctl -u soc-assistant -n 50 --no-pager` or `sudo journalctl -u wazuh-mcp-server -n 50 --no-pager`. On later starts or after changing a service configuration, use `sudo systemctl restart soc-assistant wazuh-mcp-server`. The API key is loaded from the protected file; you do not need to enter or export it again.

If you later update Node.js or Claude Code and their executable paths change, refresh only those paths without re-entering the API key:

```bash
CLAUDE_BIN_PATH="$(command -v claude || true)"
NPX_BIN_PATH="$(command -v npx || true)"
NODE_BIN_DIR="$(dirname "$NPX_BIN_PATH")"
if [ -x "$CLAUDE_BIN_PATH" ] && [ -x "$NPX_BIN_PATH" ]; then
  sed -i '/^CLAUDE_BIN=/d; /^PATH=/d' "$HOME/.config/soc-assistant/env"
  printf 'CLAUDE_BIN=%s\nPATH=%s:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n' \
    "$CLAUDE_BIN_PATH" "$NODE_BIN_DIR" >> "$HOME/.config/soc-assistant/env"
  chmod 600 "$HOME/.config/soc-assistant/env"
  sudo systemctl restart soc-assistant
else
  echo 'Claude Code or npx was not found; fix the installation/PATH before restarting the app.'
fi
unset CLAUDE_BIN_PATH NPX_BIN_PATH NODE_BIN_DIR
```

### On your workstation: open the app

In a terminal on your workstation, create the SSH tunnel. Use the same username, host, private key, and other SSH options that work when you normally connect to the VM. If your normal SSH command uses a private key with `-i`, include that same option here. Keep this terminal open while using the browser:

```bash
ssh -i /path/to/your-private-key -N -L 8080:127.0.0.1:8080 YOUR_VM_USER@YOUR_VM_HOST
```

Replace `/path/to/your-private-key`, `YOUR_VM_USER`, and `YOUR_VM_HOST` with the values from your working SSH login.

If your normal SSH login uses an agent or a default key and does not need `-i`, use this form:

```bash
ssh -N -L 8080:127.0.0.1:8080 YOUR_VM_USER@YOUR_VM_HOST
```

If you normally connect through a saved SSH config alias, use that alias instead:

```bash
ssh -N -L 8080:127.0.0.1:8080 YOUR_SSH_ALIAS
```

The `-N` option asks SSH to forward the port without opening a remote shell, so you will not see a VM login prompt or shell. After SSH authenticates, the terminal stays open quietly while the tunnel works; this is expected. If SSH prints `Permission denied (publickey)` and exits, authentication failed and the tunnel is not connected. Retry with the same private key and username used by your successful SSH login.

Open <http://127.0.0.1:8080> in your workstation's browser. The address is local to your workstation; the SSH tunnel forwards it to Flask on the VM. Do not open port `8080` to the internet. In the app, try a read-only prompt such as: `Show the five most recent Wazuh alerts with their time, rule description, severity, and agent.` Confirm the response contains data from your deployment. When finished, stop the tunnel with `Ctrl+C` in the workstation terminal. On the VM, stop or start either service with `sudo systemctl stop soc-assistant` / `sudo systemctl start soc-assistant` or `sudo systemctl stop wazuh-mcp-server` / `sudo systemctl start wazuh-mcp-server`. Both are enabled to start after a reboot.

## Scope and operating notes

- The interface is for one local analyst at a time. Do not expose it to a network.
- The app allows Wazuh and Shodan MCP tools and blocks shell, file-editing, and web tools in its Claude Code invocation.
- Use read-only Wazuh credentials. Server-side Wazuh permissions are the access control.
- The assistant provides triage assistance. Verify findings in Wazuh; response actions are outside this demo's scope.
- Machine-wide Claude Code restrictions and the optional prompt-guard hook are not installed by this repository.
- Local chat history and pseudonym mappings are retained for up to seven days.

## Local data and secrets

The app creates `history.db`, `pseudo.db`, and `audit.log` beside `app.py`. They may contain conversation text, pseudonym mappings, Shodan query arguments, and privacy-filter summaries. Keep them local and protected; `.gitignore` excludes these files, the local privacy config, credentials, and virtual environments. Do not commit API keys, passwords, `.env` files, or local Claude configuration.

## Repository contents

- `app.py`, `static/index.html`: Flask chat application and browser UI.
- `privacy.py`, `privacy_plus.py`: masking, response scrubbing, and privacy rules.
- `privacy_proxy.py`: stdio privacy proxy for Shodan MCP traffic.
- `wazuh_http_bridge.py`: local stdio-to-Streamable-HTTP bridge; detokenizes Wazuh requests and scrubs responses.
- `privacy_notes.py`: privacy-filter summary appended to answers.
- `privacy_config.example.json`: safe starter configuration; copy it to the ignored local `privacy_config.json` and customize it.
- `integrations/`: pinned MCP dependency metadata and a credential-free Wazuh MCP environment template.
- `test_privacy.py`: privacy-layer self-check supplied with this build.
- `test_app.py`: Flask API smoke tests with Claude mocked.
- `test_wazuh_http_bridge.py`: local protocol check for bridge authentication, identifier restoration, and response scrubbing.
- `deploy/`: systemd service examples for the app and Wazuh MCP server, plus the MCP service launcher.

## License and third-party credit

This project is licensed under Apache-2.0; see [LICENSE](LICENSE). Third-party projects keep their own names, licenses, and copyright. This SOC Assistant is an independent integration and is not endorsed by the projects below.

| Project or component | Credit and role here |
| --- | --- |
| [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | Credit to the GenSecAI project (`gensecaihq`) and its [contributors](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/ACKNOWLEDGMENTS.md). Replication installs from [the project maintainer's fork](https://github.com/efamharris/Wazuh-MCP-Server) so upstream changes do not alter the setup automatically. The fork is a controlled install source, not a claim of MCP server authorship. Updates are brought into the fork deliberately after review and compatibility testing. See the upstream [MIT license](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/LICENSE). |
| [Shodan MCP server](https://github.com/w0h1v/mcp-shodan) | Credit to the source repository and its contributors (`w0h1v`). This project runs the published npm package [`@burtthecoder/mcp-shodan`](https://www.npmjs.com/package/@burtthecoder/mcp-shodan); the GitHub source and npm package scope are both identified because they use different names. See the source project's [MIT license](https://github.com/w0h1v/mcp-shodan/blob/main/LICENSE). |
| [Wazuh](https://wazuh.com/) | The security monitoring platform queried by the Wazuh MCP server. |
| [Model Context Protocol](https://modelcontextprotocol.io/) and [Python MCP SDK](https://github.com/modelcontextprotocol/python-sdk) | The protocol and Python SDK used by the local integration bridge. |
| [Anthropic Claude Code](https://docs.anthropic.com/en/docs/claude-code/overview) | The CLI agent used by the assistant to interpret analyst questions and call the configured MCP tools. |
| [Flask](https://flask.palletsprojects.com/) | The web framework used for the assistant's local browser interface. |

The maintained fork's `main` branch changes only when its maintainer deliberately updates it. A fresh replica uses the branch contents available at installation time. See the upstream projects for full contributor acknowledgments and license terms.
