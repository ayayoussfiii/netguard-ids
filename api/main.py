"""
main.py
───────
FastAPI application exposing:
  GET  /alerts          — paginated alert list
  GET  /alerts/{id}     — single alert with SHAP + MITRE report
  WS   /stream          — real-time alert WebSocket feed
  POST /explain         — on-demand RAG report for an alert
  GET  /stats           — detection statistics
"""

import os
import json
import asyncio
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from loguru import logger
from dotenv import load_dotenv

from rag.pipeline import generate_report

load_dotenv()

app = FastAPI(
    title="NetGuard IDS",
    description="Real-time HIDS powered by BETH dataset, XGBoost, and MITRE ATT&CK RAG",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── In-memory store (replace with PostgreSQL in production) ───────────────────

_alerts: list[dict] = []
_connected_ws: list[WebSocket] = []


# ── WebSocket manager ─────────────────────────────────────────────────────────

class ConnectionManager:
    def __init__(self):
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self._connections.append(ws)
        logger.info(f"WebSocket connected — {len(self._connections)} active")

    def disconnect(self, ws: WebSocket):
        self._connections.remove(ws)

    async def broadcast(self, data: dict):
        dead = []
        for ws in self._connections:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)


manager = ConnectionManager()


# ── Kafka consumer background task ────────────────────────────────────────────

async def consume_alerts():
    """Background task: reads from alerts.output Kafka topic and broadcasts."""
    from kafka import KafkaConsumer
    BROKER = os.getenv("KAFKA_BROKER",        "localhost:9092")
    TOPIC  = os.getenv("KAFKA_TOPIC_OUTPUT",  "alerts.output")

    loop     = asyncio.get_event_loop()
    consumer = await loop.run_in_executor(None, lambda: KafkaConsumer(
        TOPIC,
        bootstrap_servers=BROKER,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    ))

    logger.info(f"Alert consumer listening on [{TOPIC}]")

    while True:
        records = await loop.run_in_executor(
            None, lambda: consumer.poll(timeout_ms=100)
        )
        for tp, msgs in records.items():
            for msg in msgs:
                alert = msg.value
                alert["id"] = len(_alerts)
                _alerts.append(alert)
                await manager.broadcast({"type": "alert", "data": alert})
        await asyncio.sleep(0.01)


@app.on_event("startup")
async def startup():
    asyncio.create_task(consume_alerts())


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/alerts", summary="Paginated alert list")
def get_alerts(
    page:  int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    label: Optional[str] = Query(None, description="Filter by xgb_label: SUS | EVIL"),
):
    filtered = _alerts
    if label:
        filtered = [a for a in _alerts if a.get("xgb_label") == label.upper()]

    start = (page - 1) * limit
    end   = start + limit
    return {
        "total":   len(filtered),
        "page":    page,
        "limit":   limit,
        "alerts":  filtered[start:end],
    }


@app.get("/alerts/{alert_id}", summary="Single alert with SHAP and MITRE report")
def get_alert(alert_id: int):
    if alert_id < 0 or alert_id >= len(_alerts):
        raise HTTPException(status_code=404, detail="Alert not found")
    return _alerts[alert_id]


@app.websocket("/stream")
async def websocket_stream(ws: WebSocket):
    """Real-time alert stream via WebSocket."""
    await manager.connect(ws)
    try:
        while True:
            await ws.receive_text()   # keep alive
    except WebSocketDisconnect:
        manager.disconnect(ws)


class ExplainRequest(BaseModel):
    alert_id: int


@app.post("/explain", summary="Generate RAG report for an alert")
async def explain(req: ExplainRequest):
    if req.alert_id < 0 or req.alert_id >= len(_alerts):
        raise HTTPException(status_code=404, detail="Alert not found")

    alert  = _alerts[req.alert_id]
    loop   = asyncio.get_event_loop()
    report = await loop.run_in_executor(None, generate_report, alert)

    if report is None:
        raise HTTPException(status_code=500, detail="RAG pipeline failed")

    # Attach report to alert
    _alerts[req.alert_id]["mitre_report"] = report
    await manager.broadcast({"type": "report", "alert_id": req.alert_id, "data": report})

    return report


@app.get("/stats", summary="Detection statistics")
def get_stats():
    total  = len(_alerts)
    evil   = sum(1 for a in _alerts if a.get("xgb_label") == "EVIL")
    sus    = sum(1 for a in _alerts if a.get("xgb_label") == "SUS")
    hosts  = list({a["event"].get("hostName", "") for a in _alerts})

    if_scores = [a["if_score"] for a in _alerts]
    avg_if    = round(sum(if_scores) / len(if_scores), 4) if if_scores else 0

    return {
        "total_alerts":       total,
        "evil_alerts":        evil,
        "sus_alerts":         sus,
        "unique_hosts":       len(hosts),
        "avg_if_score":       avg_if,
        "reports_generated":  sum(1 for a in _alerts if "mitre_report" in a),
    }


@app.get("/health")
def health():
    return {"status": "ok", "alerts_in_memory": len(_alerts)}
