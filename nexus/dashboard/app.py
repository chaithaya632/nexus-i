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
import hmac
import json
import logging
import os
import secrets
import sys
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Query, Request, WebSocket, WebSocketDisconnect
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import HTMLResponse, JSONResponse, Response
    from fastapi.staticfiles import StaticFiles

    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False

from nexus import __version__
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

    def __init__(self, engine: NexusEngine | None = None, api_token: str | None = None) -> None:
        _check_fastapi()
        self.engine = engine or NexusEngine()
        if not self.engine._booted:
            self.engine.boot()

        tok = (
            api_token
            or getattr(self.engine.config, "dashboard_token", None)
            or os.environ.get("NEXUS_DASHBOARD_TOKEN")
            or ""
        ).strip()
        self.api_token: str | None = tok or None

        self.app = FastAPI(title="NEXUS Dashboard", version=__version__)
        self._ws_clients: list[WebSocket] = []
        if getattr(self.engine, "on_progress", None) is None:
            self.engine.on_progress = self.broadcast
        self._setup_routes()
        self.app.add_middleware(
            CORSMiddleware,
            allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
            allow_credentials=False,
            allow_methods=["GET", "OPTIONS"],
            allow_headers=["*"],
        )

    def _require_db(self):
        if self.engine.db is None:
            raise RuntimeError("Engine database is not initialized.")
        return self.engine.db

    # ── Route Setup ───────────────────────────────────────────────

    def _setup_routes(self) -> None:
        app = self.app

        @app.middleware("http")
        async def _require_api_token(request: Request, call_next):
            if (
                self.api_token
                and request.url.path.startswith("/api/")
                and request.method != "OPTIONS"
            ):
                auth_hdr = request.headers.get("authorization", "")
                bearer = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else ""
                supplied = bearer or request.headers.get("x-nexus-token", "").strip()
                if not supplied or not hmac.compare_digest(
                    supplied.encode("utf-8"), self.api_token.encode("utf-8")
                ):
                    return JSONResponse({"error": "Unauthorized"}, status_code=401)
            return await call_next(request)

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
            db = self._require_db()
            engs = db.list_engagements()
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
            db = self._require_db()
            if not db.get_engagement(eng_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            findings = db.get_findings(eng_id)
            if not include_suppressed:
                findings = [f for f in findings if not getattr(f, "false_positive", False)]
            out: list[dict[str, Any]] = []
            for f in findings:
                item = f.model_dump() if hasattr(f, "model_dump") else dict(f)
                if not item.get("remediation") and getattr(self.engine, "remediation", None):
                    rem = self.engine.remediation.get_for_finding(
                        item.get("cwe_id", ""), item.get("cve_ids") or []
                    )
                    if rem:
                        item["remediation"] = rem.short_fix or rem.detailed_fix
                out.append(item)
            return out

        @app.get("/api/engagements/{eng_id}/sarif")
        async def get_sarif(eng_id: str):
            db = self._require_db()
            try:
                data = build_report_data(db, eng_id)
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
            db = self._require_db()
            try:
                return diff_engagements(db, old, new)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=404)

        @app.get("/api/engagements/{eng_id}/priority")
        async def get_engagement_priority(eng_id: str, top_n: int = Query(15, ge=1, le=200)):
            from nexus.correlator.prioritize import build_remediation_plan

            db = self._require_db()
            if not db.get_engagement(eng_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            findings = db.get_findings(eng_id)
            chains = db.get_chains(eng_id)
            return build_remediation_plan(findings, chains, top_n=top_n)

        @app.get("/api/engagements/{eng_id}/chains")
        async def get_chains(eng_id: str):
            db = self._require_db()
            if not db.get_engagement(eng_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            chains = db.get_chains(eng_id)
            return [c.model_dump() if hasattr(c, "model_dump") else c for c in chains]

        @app.get("/api/engagements/{eng_id}/targets")
        async def get_targets(eng_id: str):
            db = self._require_db()
            if not db.get_engagement(eng_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            targets = db.get_targets(eng_id)
            return [t.model_dump() if hasattr(t, "model_dump") else t for t in targets]

        @app.get("/api/engagements/{eng_id}/proxy")
        async def get_engagement_proxy(eng_id: str, limit: int = Query(200, ge=1, le=1000)):
            db = self._require_db()
            if not db.get_engagement(eng_id):
                return JSONResponse({"error": "not found"}, status_code=404)
            if not hasattr(db, "get_proxy_history"):
                return []
            entries = db.get_proxy_history(eng_id, limit=limit)
            return [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in entries]

        @app.get("/api/proxy/history")
        async def get_all_proxy_history(limit: int = Query(200, ge=1, le=1000)):
            db = self._require_db()
            if not hasattr(db, "get_proxy_history"):
                return []
            entries = db.get_proxy_history("", limit=limit)
            return [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in entries]

        @app.get("/api/proxy/diff")
        async def diff_proxy_exchanges(left: str, right: str):
            import difflib

            db = self._require_db()
            if not hasattr(db, "get_proxy_entry"):
                return JSONResponse({"error": "proxy history not supported"}, status_code=501)
            e_left = db.get_proxy_entry(left)
            e_right = db.get_proxy_entry(right)
            if not e_left or not e_right:
                return JSONResponse({"error": "proxy entry not found"}, status_code=404)
            diff_lines = list(
                difflib.unified_diff(
                    e_left.response_body.splitlines(),
                    e_right.response_body.splitlines(),
                    fromfile=f"{e_left.method} {e_left.url} ({e_left.status_code})",
                    tofile=f"{e_right.method} {e_right.url} ({e_right.status_code})",
                    lineterm="",
                )
            )
            return {
                "left": e_left.model_dump(mode="json"),
                "right": e_right.model_dump(mode="json"),
                "status_changed": e_left.status_code != e_right.status_code,
                "diff": "\n".join(diff_lines[:300]),
            }

        @app.post("/api/proxy/replay")
        async def replay_proxy_exchange(request: Request):
            """Scope-enforced HTTP Repeater endpoint: replay or mutate a captured request."""
            import httpx

            from nexus.core.scope import ScopeViolation
            from nexus.db.models import ProxyEntry
            from nexus.recon.runner import validate_headers
            from nexus.scanner._http import make_http_client, parse_url_target, redact_headers

            try:
                payload = await request.json()
            except ValueError:
                return JSONResponse({"error": "Valid JSON body required"}, status_code=400)
            if not isinstance(payload, dict):
                return JSONResponse({"error": "JSON object body required"}, status_code=400)

            db = self._require_db()
            base_entry = None
            entry_id = str(payload.get("entry_id") or "").strip()
            if entry_id and hasattr(db, "get_proxy_entry"):
                base_entry = db.get_proxy_entry(entry_id)
                if base_entry is None:
                    return JSONResponse({"error": "proxy entry not found"}, status_code=404)

            method = str(
                payload.get("method") or (base_entry.method if base_entry else "GET")
            ).upper()
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                return JSONResponse(
                    {"error": f"Unsupported HTTP method: {method}"}, status_code=400
                )

            url = str(payload.get("url") or (base_entry.url if base_entry else "")).strip()
            if not url.startswith(("http://", "https://")):
                return JSONResponse({"error": "Valid http(s) URL required"}, status_code=400)

            host, port, _ = parse_url_target(url)
            if not host:
                return JSONResponse({"error": "Valid http(s) host required"}, status_code=400)
            if self.engine.scope is not None:
                try:
                    self.engine.scope.enforce(host, port, check_dns=True)
                except ScopeViolation as exc:
                    return JSONResponse({"error": str(exc)}, status_code=403)
            else:
                return JSONResponse(
                    {"error": "Active engagement scope required before replaying requests"},
                    status_code=403,
                )

            req_headers = dict(base_entry.request_headers) if base_entry else {}
            if isinstance(payload.get("headers"), dict):
                req_headers.update({str(k): str(v) for k, v in payload["headers"].items()})
            try:
                req_headers = validate_headers(req_headers)
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)

            req_body = (
                str(payload["body"])
                if "body" in payload and payload["body"] is not None
                else (base_entry.request_body if base_entry else "")
            )

            try:
                async with make_http_client(timeout=20.0, follow_redirects=False) as client:
                    resp = await client.request(
                        method,
                        url,
                        headers=req_headers or None,
                        content=req_body.encode("utf-8") if req_body else None,
                    )
            except httpx.HTTPError as exc:
                return JSONResponse({"error": f"Upstream request failed: {exc}"}, status_code=502)

            eng_id = str(
                payload.get("engagement_id")
                or (base_entry.engagement_id if base_entry else "")
                or (self.engine._current_engagement or "")
            )
            recorded = ProxyEntry(
                engagement_id=eng_id,
                method=method,
                url=url,
                host=host,
                port=port or 80,
                status_code=resp.status_code,
                request_headers=redact_headers(req_headers),
                request_body=req_body[:20_000],
                response_headers=redact_headers(dict(resp.headers)),
                response_body=resp.text[:50_000],
            )
            if hasattr(db, "add_proxy_entry"):
                db.add_proxy_entry(recorded)

            return recorded.model_dump(mode="json")

        # ── WebSocket ─────────────────────────────────────────────

        @app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            if self.api_token:
                auth_hdr = websocket.headers.get("authorization", "")
                bearer = auth_hdr[7:].strip() if auth_hdr.lower().startswith("bearer ") else ""
                hdr_tok = bearer or websocket.headers.get("x-nexus-token", "").strip()
                if hdr_tok:
                    if not hmac.compare_digest(
                        hdr_tok.encode("utf-8"), self.api_token.encode("utf-8")
                    ):
                        await websocket.close(code=1008)
                        return
                    await websocket.accept()
                else:
                    # Reject query-string tokens so secrets never appear in URLs/logs;
                    # require initial auth frame: {"type": "auth", "token": "..."}
                    await websocket.accept()
                    try:
                        first_msg = await asyncio.wait_for(websocket.receive_text(), timeout=5.0)
                        payload = json.loads(first_msg)
                        frame_tok = (
                            str(payload.get("token", "")).strip()
                            if isinstance(payload, dict) and payload.get("type") == "auth"
                            else ""
                        )
                    except (TimeoutError, WebSocketDisconnect, ValueError, TypeError):
                        try:
                            await websocket.close(code=1008)
                        except Exception:
                            pass
                        return
                    if not frame_tok or not hmac.compare_digest(
                        frame_tok.encode("utf-8"), self.api_token.encode("utf-8")
                    ):
                        await websocket.close(code=1008)
                        return
                    await websocket.send_text(json.dumps({"event": "auth", "status": "ok"}))
            else:
                await websocket.accept()

            self._ws_clients.append(websocket)
            try:
                while True:
                    # Keep alive — client can send pings
                    data = await websocket.receive_text()
                    if data == "ping":
                        await websocket.send_text("pong")
            except WebSocketDisconnect:
                pass
            finally:
                if websocket in self._ws_clients:
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
        for ws in list(self._ws_clients):
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            if ws in self._ws_clients:
                self._ws_clients.remove(ws)


def create_app(engine: NexusEngine | None = None, api_token: str | None = None) -> Any:
    """Factory function — returns the FastAPI app instance."""
    _check_fastapi()
    dash = DashboardApp(engine, api_token=api_token)
    return dash.app


def run_dashboard(
    host: str = "127.0.0.1",
    port: int = 8477,
    engine: NexusEngine | None = None,
    api_token: str | None = None,
) -> None:
    """Start the dashboard server (blocking), enforcing token auth when bound beyond loopback."""
    _check_fastapi()
    import uvicorn

    resolved_tok = (
        api_token
        or (getattr(engine.config, "dashboard_token", None) if engine else None)
        or os.environ.get("NEXUS_DASHBOARD_TOKEN")
        or ""
    ).strip() or None
    if host not in ("127.0.0.1", "::1", "localhost") and not resolved_tok:
        resolved_tok = secrets.token_urlsafe(24)
        print(
            f"[NEXUS] Non-loopback bind ({host}) auto-generated dashboard token: {resolved_tok}",
            file=sys.stderr,
            flush=True,
        )
    app = create_app(engine, api_token=resolved_tok)
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
  <div id="token-bar" style="display:none;margin:10px 0;padding:12px;background:#141828;border:1px solid #1e2a4a;border-radius:6px">
    <span style="color:#ffab00;font-size:13px;margin-right:8px">Dashboard API Token Required:</span>
    <input id="tok-input" type="password" placeholder="Enter NEXUS dashboard token" style="background:#0a0e17;color:#e0e0e0;border:1px solid #1e2a4a;padding:6px 10px;border-radius:4px">
    <button id="tok-save" style="margin-left:6px;padding:6px 12px;background:#00d4ff;color:#0a0e17;border:none;border-radius:4px;font-weight:600;cursor:pointer">Connect</button>
    <span id="tok-err" style="color:#ff1744;font-size:12px;margin-left:8px"></span>
  </div>
  <div id="status">Connecting...</div>
  <div class="cards" id="stats-cards"></div>
  <h2 style="color:#00d4ff;margin:20px 0 10px">Engagements</h2>
  <div id="engagements"><div class="empty">Loading...</div></div>
</div>
<script>
let apiToken=sessionStorage.getItem('nexus_token')||'';
function esc(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML}
function authHeaders(){return apiToken?{'X-Nexus-Token':apiToken}:{}}
async function apiFetch(url){
  const r=await fetch(url,{headers:authHeaders()});
  if(r.status===401){document.getElementById('token-bar').style.display='block';throw new Error('Unauthorized')}
  document.getElementById('token-bar').style.display='none';
  return r;
}
function saveToken(){
  apiToken=document.getElementById('tok-input').value.trim();
  if(apiToken){sessionStorage.setItem('nexus_token',apiToken)}else{sessionStorage.removeItem('nexus_token')}
  document.getElementById('tok-err').textContent='';
  load().then(()=>connectFallbackWs()).catch(()=>{document.getElementById('tok-err').textContent='Invalid token'});
}
document.getElementById('tok-save').addEventListener('click',saveToken);
document.getElementById('tok-input').addEventListener('keydown',e=>{if(e.key==='Enter')saveToken()});
async function load(){
  try{
    const sr=await apiFetch('/api/status');if(!sr.ok)throw new Error('status');const st=await sr.json();
    document.getElementById('status').innerHTML='<span class="ok">● Connected</span> | Tier: '+esc(st.tier)+' | AI: '+(st.ai&&st.ai.available?'✓ '+esc(st.ai.model):'off');
    const b=st.brain||{};
    document.getElementById('stats-cards').innerHTML=[
      card('Expert Rules',b.expert_rules||0),
      card('CVEs Loaded',b.knowledge_cves||0),
      card('Payloads',b.payloads||0),
      card('Remediations',b.remediations||0),
    ].join('');
    const er=await apiFetch('/api/engagements');if(!er.ok)throw new Error('engs');const engs=await er.json();
    if(!engs.length){document.getElementById('engagements').innerHTML='<div class="empty">No engagements yet.  Run: nexus engage &lt;target&gt;</div>';return}
    let html='<table><tr><th>ID</th><th>Name</th><th>Target</th><th>Phase</th><th>Created</th></tr>';
    engs.forEach(e=>{html+='<tr><td>'+esc(e.id)+'</td><td>'+esc(e.name)+'</td><td>'+esc(e.target)+'</td><td>'+esc(e.phase)+'</td><td>'+esc(new Date(e.created_at).toLocaleString())+'</td></tr>'});
    html+='</table>';document.getElementById('engagements').innerHTML=html;
  }catch(e){
    const msg=e&&e.message==='Unauthorized'?'● Authentication Required':'● Disconnected';
    document.getElementById('status').innerHTML='<span class="err">'+msg+'</span>';
  }
}
function card(label,value){return '<div class="card"><div class="value">'+esc(value)+'</div><div class="label">'+esc(label)+'</div></div>'}
load();setInterval(load,10000);

// WebSocket live updates with auth frame & exponential backoff
let _ws=null;
function connectFallbackWs(){
  let retryMs = 2000;
  function start(){
    try{
      if(_ws&&_ws.readyState<=1)_ws.close();
      const ws=new WebSocket((location.protocol==='https:'?'wss:':'ws:')+'//' +location.host+'/ws');
      _ws=ws;
      ws.onopen=function(){
        retryMs=2000;
        if(apiToken)ws.send(JSON.stringify({type:'auth',token:apiToken}));
      };
      ws.onmessage=function(e){try{const m=JSON.parse(e.data);if(m.event&&m.event!=='auth')load()}catch(x){}};
      ws.onclose=function(ev){if(ev.code!==1008){setTimeout(start,retryMs);retryMs=Math.min(retryMs*2,30000);}};
    }catch(e){}
  }
  start();
}
connectFallbackWs();
</script>
</body>
</html>"""
