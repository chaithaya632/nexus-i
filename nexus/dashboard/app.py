"""NEXUS Web Dashboard — FastAPI REST API + WebSocket live updates.

Optional dependency: install with `pip install nexus[dashboard]`
(requires fastapi, uvicorn).

Serves:
  GET  /api/engagements        — list all engagements
  GET  /api/engagements/{id}   — engagement summary
  GET  /api/engagements/{id}/findings  — findings list
  GET  /api/engagements/{id}/chains    — attack chains
  GET  /api/engagements/{id}/targets   — targets
  GET  /api/status             — engine status
  WS   /ws                     — live event stream
  GET  /                       — static SPA
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles
    from fastapi.middleware.cors import CORSMiddleware
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from nexus import __version__
from nexus.core.config import NexusConfig
from nexus.core.engine import NexusEngine
from nexus.correlator.diff import diff_engagements
from nexus.reporter.generator import ReportData, build_report_data
from nexus.reporter.sarif import render_sarif

log = logging.getLogger("nexus.dashboard")

STATIC_DIR = Path(__file__).parent / "static"


def _check_fastapi() -> None:
    if not HAS_FASTAPI:
        raise ImportError(
            "Dashboard requires FastAPI.  Install with: pip install 'nexus[dashboard]'"
        )


class DashboardApp:
    """Wraps the FastAPI app and engine reference."""

    def __init__(self, engine: NexusEngine | None = None) -> None:
        _check_fastapi()
        self.engine = engine or NexusEngine()
        if not self.engine._booted:
            self.engine.boot()

        self.app = FastAPI(title="NEXUS Dashboard", version=__version__)
        self.app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
            allow_credentials=False,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
        )
        self._ws_clients: list[WebSocket] = []
        self._setup_routes()

    # ── Route Setup ───────────────────────────────────────────────

    def _setup_routes(self) -> None:
        app = self.app

        @app.get("/api/status")
        async def status():
            stats = self.engine.brain_stats()
            ai_status = {}
            if hasattr(self.engine, "ai_boost") and self.engine.ai_boost:
                ai_status = self.engine.ai_boost.status()
            return {
                "version": __version__,
                "booted": self.engine._booted,
                "tier": self.engine.config.tier.value,
                "stealth": self.engine.config.stealth.value,
                "profile": self.engine.config.profile.value,
                "brain": stats,
                "ai": ai_status,
            }

        @app.get("/api/engagements")
        async def list_engagements():
            assert self.engine.db is not None
            engs = self.engine.db.list_engagements()
            return [
                {
                    "id": e.id,
                    "name": e.name,
                    "target": e.target,
                    "phase": e.phase.value,
                    "created_at": e.created_at.isoformat(),
                }
                for e in engs
            ]

        @app.get("/api/engagements/{eng_id}")
        async def get_engagement(eng_id: str):
            summary = self.engine.engagement_summary(eng_id)
            if not summary:
                return JSONResponse({"error": "not found"}, status_code=404)
            return summary

        @app.get("/api/engagements/{eng_id}/findings")
        async def get_findings(eng_id: str, include_suppressed: bool = True):
            assert self.engine.db is not None
            findings = self.engine.db.get_findings(eng_id)
            if not include_suppressed:
                findings = [f for f in findings if not getattr(f, "false_positive", False)]
            return [
                f.model_dump() if hasattr(f, "model_dump") else f
                for f in findings
            ]

        @app.get("/api/engagements/{eng_id}/sarif")
        async def get_sarif(eng_id: str):
            assert self.engine.db is not None
            try:
                data = build_report_data(self.engine.db, eng_id)
            except ValueError:
                return JSONResponse({"error": "not found"}, status_code=404)
            sarif_data = ReportData(
                meta=data.meta,
                engagement=data.engagement,
                targets=data.targets,
                findings=data.findings + data.suppressed_findings,
                chains=data.chains,
                credentials=data.credentials,
                severity_counts=data.severity_counts,
                executive_summary=data.executive_summary,
                methodology=data.methodology,
                suppressed_findings=data.suppressed_findings,
            )
            return Response(content=render_sarif(sarif_data), media_type="application/sarif+json")

        @app.get("/api/diff")
        async def get_diff(old: str, new: str):
            assert self.engine.db is not None
            try:
                return diff_engagements(self.engine.db, old, new)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=404)

        @app.get("/api/engagements/{eng_id}/chains")
        async def get_chains(eng_id: str):
            assert self.engine.db is not None
            chains = self.engine.db.get_chains(eng_id)
            return [
                c.model_dump() if hasattr(c, "model_dump") else c
                for c in chains
            ]

        @app.get("/api/engagements/{eng_id}/targets")
        async def get_targets(eng_id: str):
            assert self.engine.db is not None
            targets = self.engine.db.get_targets(eng_id)
            return [
                t.model_dump() if hasattr(t, "model_dump") else t
                for t in targets
            ]

        # ── WebSocket ─────────────────────────────────────────────

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self._ws_clients.append(websocket)
            try:
                while True:
                    # Keep alive — client can send pings
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                self._ws_clients.remove(websocket)

        # ── Static files / SPA ────────────────────────────────────

        @app.get("/", response_class=HTMLResponse)
        async def index():
            index_path = STATIC_DIR / "index.html"
            if index_path.is_file():
                return HTMLResponse(index_path.read_text(encoding="utf-8"))
            return HTMLResponse(_fallback_html())

        # Mount static assets if they exist
        if STATIC_DIR.is_dir():
            app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # ── Broadcast ─────────────────────────────────────────────────

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        """Send a JSON event to all connected WebSocket clients."""
        message = json.dumps({"event": event, "data": data})
        dead: list[WebSocket] = []
        for ws in self._ws_clients:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._ws_clients.remove(ws)


def create_app(engine: NexusEngine | None = None) -> Any:
    """Factory function — returns the FastAPI app instance."""
    _check_fastapi()
    dash = DashboardApp(engine)
    return dash.app


def run_dashboard(host: str = "127.0.0.1", port: int = 8477, engine: NexusEngine | None = None) -> None:
    """Start the dashboard server (blocking)."""
    _check_fastapi()
    import uvicorn
    app = create_app(engine)
    log.info("Starting NEXUS dashboard at http://%s:%d", host, port)
    uvicorn.run(app, host=host, port=port, log_level="info")


def _fallback_html() -> str:
    """Minimal inline HTML when static files aren't present."""
    return """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NEXUS Dashboard</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0e17;color:#e0e0e0}
.header{background:linear-gradient(135deg,#1a1a2e,#16213e);padding:20px 30px;border-bottom:2px solid #0f3460}
.header h1{color:#00d4ff;font-size:24px}
.header .sub{color:#888;font-size:14px}
.container{max-width:1200px;margin:0 auto;padding:20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:16px;margin:20px 0}
.card{background:#141828;border:1px solid #1e2a4a;border-radius:8px;padding:20px}
.card h3{color:#00d4ff;margin-bottom:10px}
.card .value{font-size:28px;font-weight:700;color:#fff}
.card .label{color:#888;font-size:12px;text-transform:uppercase;margin-top:4px}
.severity-bar{display:flex;gap:8px;margin-top:10px}
.severity-bar .badge{padding:4px 10px;border-radius:4px;font-size:12px;font-weight:600}
.crit{background:#ff1744;color:#fff}.high{background:#ff6d00;color:#fff}
.med{background:#ffab00;color:#000}.low{background:#00e676;color:#000}
.info{background:#2979ff;color:#fff}
table{width:100%;border-collapse:collapse;margin-top:16px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #1e2a4a}
th{color:#00d4ff;font-size:13px;text-transform:uppercase}
#status{padding:8px 16px;background:#1a1a2e;border-radius:4px;display:inline-block;margin:10px 0}
.ok{color:#00e676}.err{color:#ff1744}
.empty{color:#666;padding:40px;text-align:center}
</style>
</head>
<body>
<div class="header">
  <h1>⚡ NEXUS Dashboard</h1>
  <div class="sub">Network EXploration & Unified Security</div>
</div>
<div class="container">
  <div id="status">Connecting...</div>
  <div class="cards" id="stats-cards"></div>
  <h2 style="color:#00d4ff;margin:20px 0 10px">Engagements</h2>
  <div id="engagements"><div class="empty">Loading...</div></div>
</div>
<script>
function esc(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML}
async function load(){
  try{
    const sr=await fetch('/api/status');const st=await sr.json();
    document.getElementById('status').innerHTML='<span class="ok">● Connected</span> | Tier: '+esc(st.tier)+' | AI: '+(st.ai&&st.ai.available?'✓ '+esc(st.ai.model):'off');
    const b=st.brain||{};
    document.getElementById('stats-cards').innerHTML=[
      card('Expert Rules',b.expert_rules||0),
      card('CVEs Loaded',b.knowledge_cves||0),
      card('Payloads',b.payloads||0),
      card('Remediations',b.remediations||0),
    ].join('');
    const er=await fetch('/api/engagements');const engs=await er.json();
    if(!engs.length){document.getElementById('engagements').innerHTML='<div class="empty">No engagements yet.  Run: nexus engage &lt;target&gt;</div>';return}
    let html='<table><tr><th>ID</th><th>Name</th><th>Target</th><th>Phase</th><th>Created</th></tr>';
    engs.forEach(e=>{html+='<tr><td>'+esc(e.id)+'</td><td>'+esc(e.name)+'</td><td>'+esc(e.target)+'</td><td>'+esc(e.phase)+'</td><td>'+esc(new Date(e.created_at).toLocaleString())+'</td></tr>'});
    html+='</table>';document.getElementById('engagements').innerHTML=html;
  }catch(e){document.getElementById('status').innerHTML='<span class="err">● Disconnected</span>'}
}
function card(label,value){return '<div class="card"><div class="value">'+esc(value)+'</div><div class="label">'+esc(label)+'</div></div>'}
load();setInterval(load,10000);

// WebSocket live updates
try{
  const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//' +location.host+'/ws');
  ws.onmessage=function(e){try{const m=JSON.parse(e.data);if(m.event)load()}catch(x){}};
  ws.onclose=function(){setTimeout(()=>location.reload(),5000)};
}catch(e){}
</script>
</body>
</html>"""
