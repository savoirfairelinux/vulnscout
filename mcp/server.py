import os
import sys

# Ensure the mcp/ directory is on sys.path regardless of how this script is invoked.
# This allows `from client import ...` and `from tools.assessments import ...` to resolve.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.mcpserver import MCPServer
from client import VulnScoutClient
from tools.assessments import register_tools as register_assessment_tools
from tools.context import register_tools as register_context_tools
from tools.reviews import register_tools as register_review_tools
from tools.vulnerabilities import register_tools as register_vulnerability_tools


def create_server(base_url: str) -> MCPServer:
    """Create and configure the VulnScout MCP server."""
    client = VulnScoutClient(base_url)
    mcp_server = MCPServer("vulnscout")
    register_assessment_tools(mcp_server, client)
    register_context_tools(mcp_server, client)
    register_vulnerability_tools(mcp_server, client)
    register_review_tools(mcp_server, client)
    return mcp_server


if __name__ == "__main__":
    base_url = os.environ.get("VULNSCOUT_BASE_URL", "http://localhost:7275")
    server = create_server(base_url)
    server.run()
