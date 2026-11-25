"""Load the maintained Wazuh MCP checkout's .env and launch its HTTP server."""

import os
import sys

from dotenv import load_dotenv


mcp_dir = os.environ.get("WAZUH_MCP_DIR", os.getcwd())
load_dotenv(os.path.join(mcp_dir, ".env"), override=True)
os.environ.update(
    {
        "MCP_HOST": "127.0.0.1",
        "MCP_PORT": "3000",
        "ENVIRONMENT": "production",
    }
)
os.chdir(mcp_dir)
os.execvpe(sys.executable, [sys.executable, "-m", "wazuh_mcp_server"], os.environ)
