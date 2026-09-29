# VulnScout MCP

An [MCP](https://modelcontextprotocol.io) (Model Context Protocol) server that exposes [VulnScout](https://github.com/savoirfairelinux/vulnscout)'s VEX assessment and variant-context APIs as tools for LLM agents. It lets an agent read and write vulnerability assessments and variant metadata in VulnScout directly from a chat session.

## Features

- **Write VEX assessments** for a CVE across one or more packages, supporting both OpenVEX and CycloneDX VEX status/justification/response values.
- **Read assessments**, either a single assessment by ID or the full history for a given CVE.
- **Read and update variant context** (deployment environment, platform, objectives profile, notes) by variant UUID or by project/variant name.
- Thin, dependency-light implementation: a single `httpx`-based API client plus a small set of [FastMCP](https://github.com/modelcontextprotocol/python-sdk) tool modules.

## Requirements

- Python 3.9+
- A running instance of VulnScout, reachable over HTTP

## Getting started

This server speaks MCP over stdio and is meant to be launched by an MCP
client (VS Code, the Copilot CLI, etc.), not run standalone as an HTTP
service. The client starts `run_server.py` as a subprocess per session and
talks to it over stdin/stdout; there is no listening port or long-running
daemon to manage yourself.

### Bootstrap launcher

`run_server.py` is a self-contained launcher: on first run it creates a local
`venv/`, and on every run it syncs `requirements.txt` into that venv before
execing into the server, so dependency bumps are picked up automatically.
This means an MCP client can point straight at the script without any manual
setup — just clone the repo and configure a client below.

### Configure in VS Code (GitHub Copilot extension)

Add a server entry to your workspace `.vscode/mcp.json` (or run **MCP: Add
Server** from the Command Palette and choose **Workspace**/**Global**):

```json
{
  "servers": {
    "vulnscout": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/vulnscout-mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      }
    }
  }
}
```

### Configure in GitHub Copilot CLI

Either run `/mcp add` in interactive mode and fill in the form (**Type:**
STDIO, **Command:** `python3 /path/to/vulnscout-mcp/run_server.py`,
**Environment Variables:** `{"VULNSCOUT_BASE_URL":"http://localhost:7275"}`),
or add it from the terminal:

```bash
copilot mcp add vulnscout \
  --env VULNSCOUT_BASE_URL=http://localhost:7275 \
  -- python3 /path/to/vulnscout-mcp/run_server.py
```

Or edit `~/.copilot/mcp-config.json` directly:

```json
{
  "mcpServers": {
    "vulnscout": {
      "type": "local",
      "command": "python3",
      "args": ["/path/to/vulnscout-mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      },
      "tools": ["*"]
    }
  }
}
```

### Run manually (for development/testing only)

You can invoke the server directly with stdio to exercise it outside a full
MCP client (e.g. with the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector)),
but this is not a supported way to run it in production — it is not an HTTP
server and has no standalone service mode:

```bash
pip install -r requirements.txt
export VULNSCOUT_BASE_URL=http://localhost:7275  # optional, this is the default
python server.py
```

## Configuration

| Environment variable | Default                 | Description                          |
| --------------------- | ------------------------ | ------------------------------------ |
| `VULNSCOUT_BASE_URL`  | `http://localhost:7275` | Base URL of the VulnScout API server |

## Available tools

| Tool                          | Description                                                        |
| ------------------------------ | -------------------------------------------------------------------- |
| `write_assessment`             | Create a VEX assessment for a CVE on one or more packages/variants  |
| `get_assessment`                | Retrieve a single VEX assessment by ID                               |
| `list_assessments_by_vuln`     | List all VEX assessments recorded for a CVE                          |
| `has_ai_assessment`            | Check whether a CVE already has a pending AI assessment for a variant |
| `update_ai_assessment`         | Modify the content of an existing AI-generated assessment            |
| `get_vulnerability`            | Retrieve a single vulnerability, scoped to a variant                 |
| `find_project_id`              | Resolve a project name to its UUID                                   |
| `find_variant_id`              | Resolve a project/variant name pair to a variant UUID                |
| `list_variants`                | List all variants across every project (id, name, project_id)        |
| `get_merged_context`           | Get the merged project + variant context for a variant               |
| `get_project_context`          | Get context fields for a project by UUID                             |
| `update_project_context`       | Update the description of a project                                  |
| `update_variant_context`       | Update context fields for a variant by UUID (partial updates)       |
| `get_custom_assessment`        | Fetch a single user/custom assessment, with any existing per-target AI reviews |
| `list_custom_assessments`      | List user/custom assessments, optionally scoped to a project variant |
| `write_assessment_review`      | Save an AI review of one (variant, package) target of a user/custom assessment |

> [!NOTE]
> Every tool returns a plain string: either a formatted summary of the result or an `Error: ...` message. Tools never raise exceptions back to the agent.

## Project structure

```
client.py          VulnScoutClient: httpx wrapper around the VulnScout HTTP API
server.py           Builds the FastMCP server and registers tool modules
run_server.py       Self-bootstrapping launcher (creates venv, installs deps, execs server.py)
tools/
  assessments.py    Tools for reading/writing VEX assessments
  context.py        Tools for reading/updating project and variant context
  reviews.py        Tools for reading custom assessments and writing reviews
  vulnerabilities.py  Tool for reading a vulnerability, optionally variant-scoped
tests/              pytest + respx test suite
```

## Development

Install dependencies (including test-only ones):

```bash
pip install -r requirements.txt
```

Run the test suite from the repo root:

```bash
pytest -q
```

Run a single test:

```bash
pytest tests/test_assessments.py::TestWriteAssessmentImpl::test_api_error_returns_error_string -q
```

See [`.github/copilot-instructions.md`](.github/copilot-instructions.md) for a deeper look at the architecture and codebase conventions.

## License

This project is licensed under the [GNU General Public License v3.0 only](LICENSE).
