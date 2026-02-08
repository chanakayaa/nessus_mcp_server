# Nessus MCP Server

A Model Context Protocol (MCP) server for interacting with **Nessus** vulnerability scanner. This server exposes Nessus functionality as MCP tools, resources, and prompts — enabling AI assistants like Claude to manage scans, analyze vulnerabilities, and generate reports.

## Features

### 🔧 Tools (30+)

| Category | Tools |
|----------|-------|
| **Authentication** | `nessus_login`, `nessus_server_info`, `nessus_server_status` |
| **Scan Management** | `nessus_list_scans`, `nessus_create_scan`, `nessus_launch_scan`, `nessus_pause_scan`, `nessus_resume_scan`, `nessus_stop_scan`, `nessus_delete_scan`, `nessus_configure_scan` |
| **Scan Results** | `nessus_get_scan_details`, `nessus_get_host_details`, `nessus_get_plugin_output`, `nessus_search_vulnerabilities`, `nessus_get_scan_history` |
| **Export** | `nessus_export_scan`, `nessus_download_export` |
| **Templates & Policies** | `nessus_list_templates`, `nessus_list_policies` |
| **Folders** | `nessus_list_folders`, `nessus_create_folder`, `nessus_delete_folder` |
| **Plugins** | `nessus_list_plugin_families`, `nessus_get_plugin_family`, `nessus_get_plugin_details`, `nessus_list_plugin_rules` |
| **System** | `nessus_list_scanners`, `nessus_list_users`, `nessus_list_timezones` |

### 📚 Resources
- `nessus://server/info` — Server metadata
- `nessus://scans/list` — All scans overview
- `nessus://templates/list` — Available scan templates

### 💡 Prompts
- `vulnerability_report` — Generate a vulnerability assessment report
- `compare_scans` — Compare two scan results
- `scan_creation_wizard` — Guided scan creation

---

## Installation

### Prerequisites
- Python 3.10+
- Nessus scanner running (tested with Nessus Expert 10.x)
- MCP SDK (`pip install mcp`)

### Setup

```bash
# Clone or copy the server files
cd nessus-mcp

# Install dependencies
pip install -r requirements.txt

# Set environment variables (or use defaults)
export NESSUS_URL="https://localhost:8834"
export NESSUS_USERNAME="zoro"
export NESSUS_PASSWORD="zoro"

# Test the server
python nessus_mcp_server.py
```

---

## Configuration

### Claude Desktop

Add to your Claude Desktop config (`%APPDATA%\Claude\claude_desktop_config.json` on Windows or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "nessus": {
      "command": "python",
      "args": ["C:\\path\\to\\nessus_mcp_server.py"],
      "env": {
        "NESSUS_URL": "https://localhost:8834",
        "NESSUS_USERNAME": "your_username",
        "NESSUS_PASSWORD": "your_password"
      }
    }
  }
}
```

### Claude Code

```bash
claude mcp add nessus -- python /path/to/nessus_mcp_server.py
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NESSUS_URL` | `https://localhost:8834` | Nessus server URL |
| `NESSUS_USERNAME` | `zoro` | Authentication username |
| `NESSUS_PASSWORD` | `zoro` | Authentication password |

---

## Usage Examples

### List all scans
```
> Use nessus_list_scans to show me all current scans
```

### Create and launch a scan
```
> Create a basic network scan targeting 192.168.1.0/24 named "Internal Network Audit"
> Then launch it
```

### Analyze scan results
```
> Show me the details of scan 5, focusing on critical and high severity findings
```

### Search for specific vulnerabilities
```
> Search scan 5 for any SSL/TLS related vulnerabilities
```

### Export results
```
> Export scan 5 as a CSV file
```

### Get plugin details
```
> Show me details about Nessus plugin 10287
```

---

## Architecture

```
┌─────────────────┐     stdio      ┌──────────────────┐    HTTPS/REST    ┌─────────────┐
│  Claude / LLM   │ ◄────────────► │  Nessus MCP      │ ◄──────────────► │   Nessus    │
│  (MCP Client)   │                │  Server           │                  │   Scanner   │
└─────────────────┘                └──────────────────┘                  └─────────────┘
```

- **Transport**: stdio (standard input/output)
- **Auth**: Session-based token authentication with Nessus API
- **SSL**: Self-signed certificate validation is disabled (standard for local Nessus)

---

## Security Notes

- Credentials are passed via environment variables (not hardcoded in production)
- SSL certificate verification is disabled to support Nessus's self-signed certificates
- The server authenticates once and reuses the session token
- For production use, consider implementing token rotation and secure credential storage

---

## API Coverage

This server covers the core Nessus REST API endpoints:

| Endpoint | Methods | Covered |
|----------|---------|---------|
| `/session` | POST | ✅ |
| `/server/properties` | GET | ✅ |
| `/server/status` | GET | ✅ |
| `/scans` | GET, POST | ✅ |
| `/scans/{id}` | GET, PUT, DELETE | ✅ |
| `/scans/{id}/launch` | POST | ✅ |
| `/scans/{id}/pause` | POST | ✅ |
| `/scans/{id}/resume` | POST | ✅ |
| `/scans/{id}/stop` | POST | ✅ |
| `/scans/{id}/export` | POST | ✅ |
| `/scans/{id}/hosts/{id}` | GET | ✅ |
| `/scans/{id}/hosts/{id}/plugins/{id}` | GET | ✅ |
| `/editor/scan/templates` | GET | ✅ |
| `/policies` | GET | ✅ |
| `/folders` | GET, POST, DELETE | ✅ |
| `/plugins/families` | GET | ✅ |
| `/plugins/families/{id}` | GET | ✅ |
| `/plugins/plugin/{id}` | GET | ✅ |
| `/plugin-rules` | GET | ✅ |
| `/scanners` | GET | ✅ |
| `/users` | GET | ✅ |
| `/scans/timezones` | GET | ✅ |

---

## License

MIT License
