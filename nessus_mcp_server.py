#!/usr/bin/env python3
"""
Nessus MCP Server
A Model Context Protocol server for interacting with Nessus vulnerability scanner.
Provides tools for managing scans, viewing results, exporting reports, and more.
"""

import json
import ssl
import urllib.request
import urllib.parse
import urllib.error
import os
import time
import logging
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nessus-mcp")

# ─────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────
NESSUS_URL = os.environ.get("NESSUS_URL", "https://localhost:8834")
NESSUS_USERNAME = os.environ.get("NESSUS_USERNAME", "zoro")
NESSUS_PASSWORD = os.environ.get("NESSUS_PASSWORD", "zoro")

# Create MCP server
mcp = FastMCP("Nessus MCP Server")

# ─────────────────────────────────────────────────
# HTTP Client for Nessus API
# ─────────────────────────────────────────────────
class NessusClient:
    """HTTP client for the Nessus REST API."""

    def __init__(self, url: str, username: str, password: str):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.token: Optional[str] = None
        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

    def _request(self, method: str, endpoint: str, data: dict = None, raw: bool = False) -> Any:
        """Make an HTTP request to Nessus API."""
        url = f"{self.url}{endpoint}"
        headers = {"Content-Type": "application/json"}

        if self.token:
            headers["X-Cookie"] = f"token={self.token}"

        body = json.dumps(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers, method=method)

        try:
            resp = urllib.request.urlopen(req, context=self.ssl_ctx, timeout=60)
            content = resp.read()
            if raw:
                return content
            if content:
                return json.loads(content.decode())
            return {}
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ""
            raise Exception(f"Nessus API error {e.code}: {error_body}")

    def login(self) -> str:
        """Authenticate and get session token."""
        result = self._request("POST", "/session", {
            "username": self.username,
            "password": self.password,
        })
        self.token = result["token"]
        return self.token

    def ensure_auth(self):
        """Ensure we have a valid session token."""
        if not self.token:
            self.login()

    def get(self, endpoint: str, raw: bool = False) -> Any:
        self.ensure_auth()
        return self._request("GET", endpoint, raw=raw)

    def post(self, endpoint: str, data: dict = None) -> Any:
        self.ensure_auth()
        return self._request("POST", endpoint, data)

    def put(self, endpoint: str, data: dict = None) -> Any:
        self.ensure_auth()
        return self._request("PUT", endpoint, data)

    def delete(self, endpoint: str) -> Any:
        self.ensure_auth()
        return self._request("DELETE", endpoint)


# Global client instance
client = NessusClient(NESSUS_URL, NESSUS_USERNAME, NESSUS_PASSWORD)


# ─────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────
def format_timestamp(ts: int) -> str:
    """Convert Unix timestamp to human-readable string."""
    if not ts:
        return "N/A"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def format_scan_summary(scan: dict) -> str:
    """Format a single scan's info as readable text."""
    return (
        f"  ID: {scan.get('id')}\n"
        f"  Name: {scan.get('name')}\n"
        f"  Status: {scan.get('status')}\n"
        f"  Owner: {scan.get('owner', 'N/A')}\n"
        f"  Folder ID: {scan.get('folder_id', 'N/A')}\n"
        f"  Type: {scan.get('type', 'N/A')}\n"
        f"  Created: {format_timestamp(scan.get('creation_date', 0))}\n"
        f"  Modified: {format_timestamp(scan.get('last_modification_date', 0))}\n"
    )


# ═════════════════════════════════════════════════
# SERVER INFO & AUTH TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_server_info() -> str:
    """
    Get Nessus server properties and version information.
    Returns server version, license type, platform, plugin set, and other metadata.
    """
    try:
        info = client.get("/server/properties")
        return (
            f"Nessus Server Information\n"
            f"{'='*40}\n"
            f"Version: {info.get('server_version', 'N/A')}\n"
            f"UI Version: {info.get('nessus_ui_version', 'N/A')}\n"
            f"Type: {info.get('nessus_type', 'N/A')}\n"
            f"Platform: {info.get('platform', 'N/A')}\n"
            f"Plugin Set: {info.get('plugin_set', 'N/A')}\n"
            f"Loaded Plugin Set: {info.get('loaded_plugin_set', 'N/A')}\n"
            f"UUID: {info.get('server_uuid', 'N/A')}\n"
            f"License Type: {info.get('license', {}).get('type', 'N/A')}\n"
            f"License Name: {info.get('license', {}).get('name', 'N/A')}\n"
            f"Expiration: {format_timestamp(info.get('expiration', 0))}\n"
            f"Feed Error: {info.get('feed_error_message', 'None')}\n"
        )
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_server_status() -> str:
    """
    Get the current status of the Nessus server.
    Returns server status including whether it's running, restarting, etc.
    """
    try:
        status = client.get("/server/status")
        return f"Server Status\n{'='*30}\n{json.dumps(status, indent=2)}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_login(username: str = "", password: str = "") -> str:
    """
    Authenticate to the Nessus server.
    Uses environment credentials by default, or provide custom credentials.

    Args:
        username: Nessus username (optional, uses env var if empty)
        password: Nessus password (optional, uses env var if empty)
    """
    try:
        if username and password:
            client.username = username
            client.password = password
        client.token = None  # Force re-auth
        token = client.login()
        return f"Successfully authenticated. Session token obtained."
    except Exception as e:
        return f"Authentication failed: {e}"


# ═════════════════════════════════════════════════
# SCAN MANAGEMENT TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_scans(folder_id: int = 0) -> str:
    """
    List all scans, optionally filtered by folder.

    Args:
        folder_id: Filter by folder ID (0 = all folders)
    """
    try:
        result = client.get("/scans")
        scans = result.get("scans", []) or []
        folders = result.get("folders", []) or []

        if folder_id:
            scans = [s for s in scans if s.get("folder_id") == folder_id]

        output = f"Folders:\n{'='*40}\n"
        for f in folders:
            output += f"  [{f['id']}] {f['name']} (type: {f['type']}, unread: {f.get('unread_count', 0)})\n"

        output += f"\nScans ({len(scans)}):\n{'='*40}\n"
        if not scans:
            output += "  No scans found.\n"
        else:
            for scan in scans:
                output += format_scan_summary(scan) + "\n"

        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_get_scan_details(scan_id: int) -> str:
    """
    Get detailed information about a specific scan including hosts and vulnerabilities.

    Args:
        scan_id: The ID of the scan to retrieve details for
    """
    try:
        result = client.get(f"/scans/{scan_id}")
        info = result.get("info", {})
        hosts = result.get("hosts", []) or []
        vulns = result.get("vulnerabilities", []) or []

        output = (
            f"Scan Details: {info.get('name', 'N/A')}\n"
            f"{'='*50}\n"
            f"Status: {info.get('status', 'N/A')}\n"
            f"Scanner: {info.get('scanner_name', 'N/A')}\n"
            f"Policy: {info.get('policy', 'N/A')}\n"
            f"Targets: {info.get('targets', 'N/A')}\n"
            f"Start Time: {format_timestamp(info.get('scan_start', 0))}\n"
            f"End Time: {format_timestamp(info.get('scan_end', 0))}\n"
            f"Host Count: {info.get('hostcount', 0)}\n"
        )

        # Severity counts
        severities = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        output += f"\nVulnerability Summary:\n{'-'*30}\n"
        sev_counts = {}
        for v in vulns:
            sev = v.get("severity", 0)
            sev_counts[sev] = sev_counts.get(sev, 0) + v.get("count", 1)
        for sev_level in sorted(sev_counts.keys(), reverse=True):
            output += f"  {severities.get(sev_level, f'Unknown({sev_level})')}: {sev_counts[sev_level]}\n"

        # Hosts
        if hosts:
            output += f"\nHosts ({len(hosts)}):\n{'-'*30}\n"
            for h in hosts[:20]:
                output += (
                    f"  {h.get('hostname', 'N/A')} "
                    f"(Critical:{h.get('critical',0)} High:{h.get('high',0)} "
                    f"Medium:{h.get('medium',0)} Low:{h.get('low',0)} Info:{h.get('info',0)})\n"
                )
            if len(hosts) > 20:
                output += f"  ... and {len(hosts) - 20} more hosts\n"

        # Top vulnerabilities
        if vulns:
            output += f"\nTop Vulnerabilities (by severity):\n{'-'*30}\n"
            sorted_vulns = sorted(vulns, key=lambda x: (-x.get("severity", 0), -x.get("count", 0)))
            for v in sorted_vulns[:25]:
                sev_name = severities.get(v.get("severity", 0), "?")
                output += (
                    f"  [{sev_name}] {v.get('plugin_name', 'N/A')} "
                    f"(Plugin: {v.get('plugin_id')}, Count: {v.get('count', 1)})\n"
                )
            if len(vulns) > 25:
                output += f"  ... and {len(vulns) - 25} more vulnerabilities\n"

        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_get_host_details(scan_id: int, host_id: int) -> str:
    """
    Get detailed vulnerability information for a specific host in a scan.

    Args:
        scan_id: The scan ID
        host_id: The host ID within the scan
    """
    try:
        result = client.get(f"/scans/{scan_id}/hosts/{host_id}")
        info = result.get("info", {})
        vulns = result.get("vulnerabilities", []) or []

        output = (
            f"Host Details\n{'='*50}\n"
            f"Hostname: {info.get('host-fqdn', info.get('host-ip', 'N/A'))}\n"
            f"IP: {info.get('host-ip', 'N/A')}\n"
            f"OS: {info.get('operating-system', 'N/A')}\n"
            f"MAC: {info.get('mac-address', 'N/A')}\n"
            f"Start: {info.get('host_start', 'N/A')}\n"
            f"End: {info.get('host_end', 'N/A')}\n"
        )

        severities = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
        output += f"\nVulnerabilities ({len(vulns)}):\n{'-'*40}\n"
        sorted_vulns = sorted(vulns, key=lambda x: (-x.get("severity", 0), -x.get("count", 0)))
        for v in sorted_vulns[:50]:
            sev_name = severities.get(v.get("severity", 0), "?")
            output += (
                f"  [{sev_name}] {v.get('plugin_name', 'N/A')} "
                f"(Plugin: {v.get('plugin_id')}, Count: {v.get('count', 1)})\n"
            )
        if len(vulns) > 50:
            output += f"  ... and {len(vulns) - 50} more\n"

        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_get_plugin_output(scan_id: int, host_id: int, plugin_id: int) -> str:
    """
    Get the output of a specific plugin for a host in a scan.
    This provides detailed vulnerability information including remediation.

    Args:
        scan_id: The scan ID
        host_id: The host ID
        plugin_id: The plugin ID to get output for
    """
    try:
        result = client.get(f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}")
        info = result.get("info", {}).get("plugindescription", {})
        outputs = result.get("outputs", []) or []

        attrs = info.get("pluginattributes", {})
        risk = attrs.get("risk_information", {})
        plugin_info = attrs.get("plugin_information", {})
        ref_info = attrs.get("ref_information", {})

        output = (
            f"Plugin Output\n{'='*50}\n"
            f"Plugin ID: {plugin_info.get('plugin_id', 'N/A')}\n"
            f"Name: {info.get('pluginname', 'N/A')}\n"
            f"Family: {info.get('pluginfamily', 'N/A')}\n"
            f"Severity: {info.get('severity', 'N/A')}\n"
            f"Risk Factor: {risk.get('risk_factor', 'N/A')}\n"
            f"CVSS Base Score: {risk.get('cvss_base_score', 'N/A')}\n"
            f"CVSS3 Base Score: {risk.get('cvss3_base_score', 'N/A')}\n"
        )

        # Description
        desc = attrs.get("description", "N/A")
        output += f"\nDescription:\n{desc}\n"

        # Solution
        solution = attrs.get("solution", "N/A")
        output += f"\nSolution:\n{solution}\n"

        # Synopsis
        synopsis = attrs.get("synopsis", "")
        if synopsis:
            output += f"\nSynopsis:\n{synopsis}\n"

        # References
        refs = ref_info.get("ref", []) or []
        if refs:
            output += f"\nReferences:\n{'-'*30}\n"
            for ref in refs[:10]:
                ref_name = ref.get("name", "N/A")
                ref_values = ref.get("values", {}).get("value", [])
                if isinstance(ref_values, list):
                    for rv in ref_values[:5]:
                        output += f"  {ref_name}: {rv}\n"
                else:
                    output += f"  {ref_name}: {ref_values}\n"

        # Plugin outputs per port
        for po in outputs[:10]:
            ports = po.get("ports", {})
            plugin_output = po.get("plugin_output", "")
            output += f"\nPort Output:\n{'-'*30}\n"
            for port, hosts_list in ports.items():
                output += f"  Port: {port}\n"
            if plugin_output:
                output += f"  Output:\n{plugin_output[:2000]}\n"

        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_create_scan(
    name: str,
    targets: str,
    template_uuid: str = "",
    template_name: str = "basic",
    description: str = "",
    folder_id: int = 0,
    policy_id: int = 0,
    enabled: bool = False,
) -> str:
    """
    Create a new scan in Nessus.

    Args:
        name: Name for the scan
        targets: Comma-separated list of targets (IPs, hostnames, CIDR ranges)
        template_uuid: UUID of the scan template (leave empty to auto-detect from template_name)
        template_name: Name of template to use: basic, discovery, advanced, webapp, malware, etc.
        description: Optional description for the scan
        folder_id: Folder ID to create scan in (0 = default)
        policy_id: Policy ID to use (0 = none)
        enabled: Whether to enable scheduled scanning
    """
    try:
        # If no UUID provided, find it from template name
        if not template_uuid:
            templates = client.get("/editor/scan/templates")
            for t in templates.get("templates", []):
                if t["name"] == template_name:
                    template_uuid = t["uuid"]
                    break
            if not template_uuid:
                return f"Error: Template '{template_name}' not found. Use nessus_list_templates to see available templates."

        settings = {
            "name": name,
            "text_targets": targets,
            "enabled": enabled,
        }
        if description:
            settings["description"] = description
        if folder_id:
            settings["folder_id"] = folder_id
        if policy_id:
            settings["policy_id"] = policy_id

        payload = {"uuid": template_uuid, "settings": settings}
        result = client.post("/scans", payload)
        scan = result.get("scan", {})
        return (
            f"Scan Created Successfully\n{'='*30}\n"
            f"Scan ID: {scan.get('id')}\n"
            f"Name: {scan.get('name')}\n"
            f"Status: {scan.get('status', 'created')}\n"
            f"Template: {template_name}\n"
            f"Targets: {targets}\n"
        )
    except Exception as e:
        return f"Error creating scan: {e}"


@mcp.tool()
def nessus_launch_scan(scan_id: int) -> str:
    """
    Launch/start a scan.

    Args:
        scan_id: The ID of the scan to launch
    """
    try:
        result = client.post(f"/scans/{scan_id}/launch")
        return f"Scan {scan_id} launched successfully. UUID: {result.get('scan_uuid', 'N/A')}"
    except Exception as e:
        return f"Error launching scan: {e}"


@mcp.tool()
def nessus_pause_scan(scan_id: int) -> str:
    """
    Pause a running scan.

    Args:
        scan_id: The ID of the scan to pause
    """
    try:
        client.post(f"/scans/{scan_id}/pause")
        return f"Scan {scan_id} paused."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_resume_scan(scan_id: int) -> str:
    """
    Resume a paused scan.

    Args:
        scan_id: The ID of the scan to resume
    """
    try:
        client.post(f"/scans/{scan_id}/resume")
        return f"Scan {scan_id} resumed."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_stop_scan(scan_id: int) -> str:
    """
    Stop a running scan.

    Args:
        scan_id: The ID of the scan to stop
    """
    try:
        client.post(f"/scans/{scan_id}/stop")
        return f"Scan {scan_id} stopped."
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_delete_scan(scan_id: int) -> str:
    """
    Delete a scan.

    Args:
        scan_id: The ID of the scan to delete
    """
    try:
        client.delete(f"/scans/{scan_id}")
        return f"Scan {scan_id} deleted."
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# EXPORT TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_export_scan(scan_id: int, format: str = "csv", chapters: str = "") -> str:
    """
    Export scan results. Returns the file ID for download.

    Args:
        scan_id: The scan ID to export
        format: Export format - 'nessus', 'csv', 'html', 'pdf', 'db'
        chapters: For PDF/HTML, semicolon-separated chapters: vuln_hosts_summary, vuln_by_host, 
                  compliance_exec, remediations, vuln_by_plugin, compliance
    """
    try:
        payload = {"format": format}
        if chapters and format in ("html", "pdf"):
            payload["chapters"] = chapters

        result = client.post(f"/scans/{scan_id}/export", payload)
        file_id = result.get("file")
        token = result.get("token", "")

        # Poll for export completion
        for _ in range(60):
            status = client.get(f"/scans/{scan_id}/export/{file_id}/status")
            if status.get("status") == "ready":
                return (
                    f"Export Ready\n{'='*30}\n"
                    f"Scan ID: {scan_id}\n"
                    f"File ID: {file_id}\n"
                    f"Format: {format}\n"
                    f"Token: {token}\n"
                    f"Download URL: {NESSUS_URL}/scans/{scan_id}/export/{file_id}/download\n"
                    f"Use nessus_download_export to download the file."
                )
            time.sleep(2)

        return f"Export initiated but not yet ready. File ID: {file_id}. Check status later."
    except Exception as e:
        return f"Error exporting scan: {e}"


@mcp.tool()
def nessus_download_export(scan_id: int, file_id: int, save_path: str = "") -> str:
    """
    Download an exported scan file.

    Args:
        scan_id: The scan ID
        file_id: The file ID from the export
        save_path: Optional path to save the file (default: /tmp/nessus_export_<scan_id>_<file_id>)
    """
    try:
        content = client.get(f"/scans/{scan_id}/export/{file_id}/download", raw=True)
        if not save_path:
            save_path = f"/tmp/nessus_export_{scan_id}_{file_id}"
        with open(save_path, "wb") as f:
            f.write(content)
        return f"Export downloaded to: {save_path} ({len(content)} bytes)"
    except Exception as e:
        return f"Error downloading: {e}"


# ═════════════════════════════════════════════════
# TEMPLATE & POLICY TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_templates(template_type: str = "scan") -> str:
    """
    List available scan or policy templates.

    Args:
        template_type: 'scan' or 'policy'
    """
    try:
        result = client.get(f"/editor/{template_type}/templates")
        templates = result.get("templates", [])

        output = f"Available {template_type.title()} Templates ({len(templates)}):\n{'='*50}\n"
        for t in templates:
            output += (
                f"  Name: {t.get('name')}\n"
                f"  Title: {t.get('title')}\n"
                f"  UUID: {t.get('uuid')}\n"
                f"  Description: {t.get('desc', 'N/A')[:100]}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_list_policies() -> str:
    """List all custom scan policies."""
    try:
        result = client.get("/policies")
        policies = result.get("policies") or []
        if not policies:
            return "No custom policies found."

        output = f"Policies ({len(policies)}):\n{'='*40}\n"
        for p in policies:
            output += (
                f"  ID: {p.get('id')}\n"
                f"  Name: {p.get('name')}\n"
                f"  Description: {p.get('description', 'N/A')}\n"
                f"  Owner: {p.get('owner', 'N/A')}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# FOLDER MANAGEMENT TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_folders() -> str:
    """List all scan folders."""
    try:
        result = client.get("/folders")
        folders = result.get("folders", [])
        output = f"Folders ({len(folders)}):\n{'='*30}\n"
        for f in folders:
            output += (
                f"  [{f['id']}] {f['name']} "
                f"(type: {f['type']}, unread: {f.get('unread_count', 'N/A')})\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_create_folder(name: str) -> str:
    """
    Create a new scan folder.

    Args:
        name: Name for the new folder
    """
    try:
        result = client.post("/folders", {"name": name})
        return f"Folder created. ID: {result.get('id', 'N/A')}"
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_delete_folder(folder_id: int) -> str:
    """
    Delete a folder.

    Args:
        folder_id: ID of the folder to delete
    """
    try:
        client.delete(f"/folders/{folder_id}")
        return f"Folder {folder_id} deleted."
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# PLUGIN TOOLS
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_plugin_families() -> str:
    """List all plugin families available in Nessus."""
    try:
        result = client.get("/plugins/families")
        families = result.get("families", [])

        output = f"Plugin Families ({len(families)}):\n{'='*50}\n"
        for fam in sorted(families, key=lambda x: x.get("name", "")):
            output += f"  [{fam.get('id')}] {fam.get('name')} ({fam.get('count', 0)} plugins)\n"
        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_get_plugin_family(family_id: int) -> str:
    """
    Get details about a plugin family and list its plugins.

    Args:
        family_id: The plugin family ID
    """
    try:
        result = client.get(f"/plugins/families/{family_id}")
        plugins = result.get("plugins", [])

        output = (
            f"Plugin Family: {result.get('name', 'N/A')}\n"
            f"{'='*40}\n"
            f"Plugins ({len(plugins)}):\n"
        )
        for p in plugins[:50]:
            output += f"  [{p.get('id')}] {p.get('name')}\n"
        if len(plugins) > 50:
            output += f"  ... and {len(plugins) - 50} more\n"
        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_get_plugin_details(plugin_id: int) -> str:
    """
    Get detailed information about a specific plugin.

    Args:
        plugin_id: The plugin ID
    """
    try:
        result = client.get(f"/plugins/plugin/{plugin_id}")
        attrs = result.get("attributes", [])

        output = (
            f"Plugin Details\n{'='*50}\n"
            f"ID: {result.get('id')}\n"
            f"Name: {result.get('name')}\n"
            f"Family: {result.get('family_name', 'N/A')}\n\n"
            f"Attributes:\n{'-'*30}\n"
        )
        for attr in attrs:
            output += f"  {attr.get('attribute_name')}: {attr.get('attribute_value', 'N/A')}\n"
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# SCANNER MANAGEMENT
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_scanners() -> str:
    """List all available scanners."""
    try:
        result = client.get("/scanners")
        scanners = result.get("scanners", [])
        if not scanners:
            return "No scanners found."

        output = f"Scanners ({len(scanners)}):\n{'='*40}\n"
        for s in scanners:
            output += (
                f"  ID: {s.get('id')}\n"
                f"  Name: {s.get('name')}\n"
                f"  Status: {s.get('status')}\n"
                f"  Type: {s.get('type', 'N/A')}\n"
                f"  Platform: {s.get('platform', 'N/A')}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# USER MANAGEMENT
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_users() -> str:
    """List all Nessus users (requires admin)."""
    try:
        result = client.get("/users")
        users = result.get("users", [])

        output = f"Users ({len(users)}):\n{'='*30}\n"
        for u in users:
            perms = {16: "Read-Only", 32: "Standard", 64: "Admin", 128: "Sysadmin"}
            output += (
                f"  ID: {u.get('id')}\n"
                f"  Username: {u.get('username')}\n"
                f"  Name: {u.get('name', 'N/A')}\n"
                f"  Email: {u.get('email', 'N/A')}\n"
                f"  Permissions: {perms.get(u.get('permissions', 0), u.get('permissions'))}\n"
                f"  Last Login: {format_timestamp(u.get('lastlogin', 0))}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# SCAN CONFIGURATION / EDITING
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_configure_scan(
    scan_id: int,
    name: str = "",
    targets: str = "",
    description: str = "",
    folder_id: int = 0,
    enabled: bool = False,
) -> str:
    """
    Update/configure an existing scan's settings.

    Args:
        scan_id: The scan ID to configure
        name: New name (empty = keep current)
        targets: New targets (empty = keep current)
        description: New description (empty = keep current)
        folder_id: New folder ID (0 = keep current)
        enabled: Enable/disable scheduled scanning
    """
    try:
        settings = {}
        if name:
            settings["name"] = name
        if targets:
            settings["text_targets"] = targets
        if description:
            settings["description"] = description
        if folder_id:
            settings["folder_id"] = folder_id
        settings["enabled"] = enabled

        result = client.put(f"/scans/{scan_id}", {"settings": settings})
        return f"Scan {scan_id} updated successfully."
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# SCAN HISTORY & TIMEZONES
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_get_scan_history(scan_id: int) -> str:
    """
    Get the run history of a scan.

    Args:
        scan_id: The scan ID
    """
    try:
        result = client.get(f"/scans/{scan_id}")
        history = result.get("history", []) or []

        output = f"Scan History for Scan {scan_id} ({len(history)} runs):\n{'='*50}\n"
        for h in history[:20]:
            output += (
                f"  History ID: {h.get('history_id')}\n"
                f"  UUID: {h.get('uuid', 'N/A')}\n"
                f"  Status: {h.get('status')}\n"
                f"  Created: {format_timestamp(h.get('creation_date', 0))}\n"
                f"  Modified: {format_timestamp(h.get('last_modification_date', 0))}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


@mcp.tool()
def nessus_list_timezones() -> str:
    """List available timezones for scheduling scans."""
    try:
        result = client.get("/scans/timezones")
        timezones = result.get("timezones", [])
        output = f"Available Timezones ({len(timezones)}):\n"
        for tz in timezones[:30]:
            output += f"  {tz.get('name', 'N/A')}: {tz.get('value', 'N/A')}\n"
        if len(timezones) > 30:
            output += f"  ... and {len(timezones) - 30} more\n"
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# PLUGIN RULES
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_list_plugin_rules() -> str:
    """List all plugin rules (custom severity modifications)."""
    try:
        result = client.get("/plugin-rules")
        rules = result.get("plugin_rules", []) or []

        if not rules:
            return "No plugin rules configured."

        output = f"Plugin Rules ({len(rules)}):\n{'='*40}\n"
        for r in rules:
            output += (
                f"  ID: {r.get('id')}\n"
                f"  Plugin ID: {r.get('plugin_id')}\n"
                f"  Type: {r.get('type')}\n"
                f"  Host: {r.get('host', '*')}\n"
                f"  Owner: {r.get('owner', 'N/A')}\n\n"
            )
        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# ADVANCED SEARCH / QUERY
# ═════════════════════════════════════════════════

@mcp.tool()
def nessus_search_vulnerabilities(scan_id: int, severity: str = "", search_text: str = "") -> str:
    """
    Search vulnerabilities in a scan by severity or text.

    Args:
        scan_id: The scan ID to search
        severity: Filter by severity: critical, high, medium, low, info (empty = all)
        search_text: Text to search in plugin names (empty = all)
    """
    try:
        result = client.get(f"/scans/{scan_id}")
        vulns = result.get("vulnerabilities", []) or []

        severity_map = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        severity_names = {0: "Info", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

        if severity:
            sev_val = severity_map.get(severity.lower())
            if sev_val is not None:
                vulns = [v for v in vulns if v.get("severity") == sev_val]

        if search_text:
            search_lower = search_text.lower()
            vulns = [v for v in vulns if search_lower in v.get("plugin_name", "").lower()]

        sorted_vulns = sorted(vulns, key=lambda x: (-x.get("severity", 0), -x.get("count", 0)))

        output = f"Search Results ({len(sorted_vulns)} vulnerabilities):\n{'='*50}\n"
        for v in sorted_vulns[:50]:
            sev_name = severity_names.get(v.get("severity", 0), "?")
            output += (
                f"  [{sev_name}] {v.get('plugin_name', 'N/A')}\n"
                f"    Plugin ID: {v.get('plugin_id')} | Count: {v.get('count', 1)}\n"
            )
        if len(sorted_vulns) > 50:
            output += f"\n  ... and {len(sorted_vulns) - 50} more results\n"

        return output
    except Exception as e:
        return f"Error: {e}"


# ═════════════════════════════════════════════════
# RESOURCES (Context for LLMs)
# ═════════════════════════════════════════════════

@mcp.resource("nessus://server/info")
def resource_server_info() -> str:
    """Nessus server information as a resource."""
    return nessus_server_info()


@mcp.resource("nessus://scans/list")
def resource_scans_list() -> str:
    """List of all Nessus scans as a resource."""
    return nessus_list_scans()


@mcp.resource("nessus://templates/list")
def resource_templates_list() -> str:
    """List of scan templates as a resource."""
    return nessus_list_templates()


# ═════════════════════════════════════════════════
# PROMPTS (Pre-built prompt templates)
# ═════════════════════════════════════════════════

@mcp.prompt()
def vulnerability_report(scan_id: int) -> str:
    """Generate a vulnerability assessment report prompt for a scan."""
    return f"""Please analyze the Nessus scan results for scan ID {scan_id} and create a comprehensive vulnerability assessment report. Include:

1. Executive Summary - high-level findings overview
2. Vulnerability Statistics - counts by severity
3. Critical & High Findings - detailed breakdown with remediation recommendations
4. Host Analysis - most vulnerable hosts
5. Remediation Priority List - ordered by risk

Start by running nessus_get_scan_details({scan_id}) to get the full scan data."""


@mcp.prompt()
def compare_scans(scan_id_1: int, scan_id_2: int) -> str:
    """Compare two scan results to identify changes."""
    return f"""Please compare the results of Nessus scan {scan_id_1} and scan {scan_id_2}. Identify:

1. New vulnerabilities introduced
2. Vulnerabilities that were remediated
3. Changes in severity levels
4. New hosts discovered
5. Overall security posture change

Start by running nessus_get_scan_details for both scan IDs."""


@mcp.prompt()
def scan_creation_wizard(target: str) -> str:
    """Help create an optimized scan for a target."""
    return f"""Help me create an optimized Nessus scan for target: {target}

First, list available templates with nessus_list_templates(), then recommend the best scan configuration based on the target type. Consider:
- Whether it's an internal or external target
- Web application vs network scan needs
- Credential requirements
- Recommended plugins/policies"""


# ═════════════════════════════════════════════════
# MAIN
# ═════════════════════════════════════════════════

if __name__ == "__main__":
    logger.info(f"Starting Nessus MCP Server (target: {NESSUS_URL})")
    mcp.run(transport="stdio")
