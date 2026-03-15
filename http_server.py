"""HTTP server — serves the web client and exposes MCP tools via REST.

This wraps the MCP tools as HTTP endpoints so the browser-based client
can call them directly, and serves the static web UI.

Run with:
    python http_server.py
Then open: http://localhost:8000
"""

from dotenv import load_dotenv
load_dotenv()

import asyncio
import json
import os
from pathlib import Path
from aiohttp import web  # type: ignore

# Import all tool functions directly
from tools import virustotal, abuseipdb, shodan
from tools.correlation import correlate_ioc, map_to_mitre
from tools.analyst_tools import generate_yara_rule, draft_ir_report
from tools.hunting import hunt_lookalike_domains, check_cve_exploitability
from tools.orchestrator import full_investigation

STATIC_DIR = Path(__file__).parent / "static"

# ── Tool registry ────────────────────────────────────────────────────────
TOOLS = {
    "vt_check_ip": lambda inp: virustotal.check_ip(inp["ip"]),
    "vt_check_domain": lambda inp: virustotal.check_domain(inp["domain"]),
    "vt_check_file_hash": lambda inp: virustotal.check_file_hash(inp["file_hash"]),
    "abuseipdb_check_ip": lambda inp: abuseipdb.check_ip(inp["ip"], inp.get("max_age_days", 90)),
    "abuseipdb_report_ip": lambda inp: abuseipdb.report_ip(inp["ip"], inp["categories"], inp.get("comment", "")),
    "shodan_lookup_ip": lambda inp: shodan.lookup_ip(inp["ip"]),
    "shodan_search": lambda inp: shodan.search(inp["query"], inp.get("page", 1)),
    "shodan_get_exploits": lambda inp: shodan.get_exploits(inp["query"]),
    "correlate_ioc_tool": lambda inp: correlate_ioc(inp["ioc"], inp.get("ioc_type", "auto")),
    "map_to_mitre_tool": lambda inp: map_to_mitre(inp["threat_description"]),
    "generate_yara_rule_tool": lambda inp: generate_yara_rule(inp["file_hash"], inp.get("rule_name", "")),
    "draft_ir_report_tool": lambda inp: draft_ir_report(
        inp["iocs"], inp.get("incident_title", "Suspected Security Incident"),
        inp.get("severity", "Medium"), inp.get("analyst_name", "SOC Analyst"),
        inp.get("affected_systems", ""),
    ),
    "hunt_lookalike_domains_tool": lambda inp: hunt_lookalike_domains(inp["domain"], inp.get("check_dns", True)),
    "check_cve_exploitability_tool": lambda inp: check_cve_exploitability(inp["cve_id"]),
    "full_investigation_tool": lambda inp: full_investigation(
        inp["iocs"], inp.get("incident_title", "Threat Investigation"), inp.get("analyst_name", "SOC Analyst")
    ),
}


# ── Handlers ─────────────────────────────────────────────────────────────

async def handle_index(request):
    index_path = STATIC_DIR / "index.html"
    return web.FileResponse(index_path)


async def handle_tool(request):
    tool_name = request.match_info["tool_name"]
    if tool_name not in TOOLS:
        return web.json_response({"error": f"Unknown tool: {tool_name}"}, status=404)

    try:
        body = await request.json()
    except Exception:
        body = {}

    try:
        result = await TOOLS[tool_name](body)
        return web.json_response({"result": result})
    except Exception as exc:
        return web.json_response({"error": str(exc)}, status=500)


async def handle_tools_list(request):
    return web.json_response({"tools": list(TOOLS.keys()), "count": len(TOOLS)})


async def handle_health(request):
    missing_keys = []
    for key in ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SHODAN_API_KEY"]:
        if not os.getenv(key):
            missing_keys.append(key)
    return web.json_response({
        "status": "ok",
        "tools": len(TOOLS),
        "missing_env_keys": missing_keys,
    })


# ── CORS middleware ───────────────────────────────────────────────────────
@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        response = web.Response()
    else:
        response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ── App setup ─────────────────────────────────────────────────────────────
def make_app():
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/", handle_index)
    app.router.add_get("/health", handle_health)
    app.router.add_get("/tools", handle_tools_list)
    app.router.add_post("/tools/{tool_name}", handle_tool)
    app.router.add_options("/tools/{tool_name}", handle_tool)
    if STATIC_DIR.exists():
        app.router.add_static("/static", STATIC_DIR)
    return app


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    print(f"\n{'='*55}")
    print(f"  SOC Copilot MCP — HTTP Server")
    print(f"{'='*55}")
    print(f"  Web UI:    http://localhost:{port}")
    print(f"  Health:    http://localhost:{port}/health")
    print(f"  Tools:     http://localhost:{port}/tools")
    print(f"  Tools available: {len(TOOLS)}")
    print(f"{'='*55}\n")
    app = make_app()
    web.run_app(app, host="0.0.0.0", port=port, print=lambda *a: None)
