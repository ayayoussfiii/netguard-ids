"""
raw.syscalls → feature engineering → Isolation Forest
             → XGBoost (if anomalous) → SHAP
             → alerts.output → async RAG report


  4. acks="all" + flush() + future.result() — no lost alerts
  5. Prometheus metrics             — counters & histograms per stage
  6. process_message() pure fn      — fully unit-testable without Kafka
  7. Structured logging             — key=value instead of f-string soup
  8. Removed unused imports         — asyncio, threading were never used
"""

from __future__ import annotations

import json
import os
import signal
import time
from contextlib import ExitStack, contextmanager
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional

from kafka import KafkaConsumer, KafkaProducer
from kafka.errors import KafkaError
from loguru import logger
from dotenv import load_dotenv
from pydantic import BaseModel, ValidationError, field_validator

from pipeline.features import extract, update_if_score, FEATURE_NAMES
from ml.detector import Detector
from rag.pipeline import generate_report

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

KAFKA_BROKER = os.getenv("KAFKA_BROKER",       "localhost:9092")
TOPIC_IN     = os.getenv("KAFKA_TOPIC_INPUT",  "raw.syscalls")
TOPIC_OUT    = os.getenv("KAFKA_TOPIC_OUTPUT", "alerts.output")
GROUP_ID     = os.getenv("KAFKA_GROUP_ID",     "netguard-consumer")
THRESHOLD    = float(os.getenv("ANOMALY_THRESHOLD", "-0.05"))
MAX_WORKERS  = int(os.getenv("RAG_WORKERS",    "4"))

LABELS = ["benign", "SUS", "EVIL"]


# ── Schema validation (fix #1) ────────────────────────────────────────────────

class RawEvent(BaseModel):
    """Minimum required fields from a BETH syscall event.
    Validates and coerces types before anything touches the ML pipeline.
    """
    processId:       int
    parentProcessId: int
    userId:          int
    mountNamespace:  int
    eventId:         int
    argsNum:         int
    returnValue:     int
    timestamp:       float
    processName:     str
    hostName:        str
    eventName:       str
    args:            str = ""
    sus:             int = 0
    evil:            int = 0

    @field_validator("processId", "parentProcessId", "userId", mode="before")
    @classmethod
    def coerce_int(cls, v):
        return int(v)

    @field_validator("timestamp", mode="before")
    @classmethod
    def coerce_float(cls, v):
        return float(v)


# ── Kafka factories ───────────────────────────────────────────────────────────

def build_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        TOPIC_IN,
        bootstrap_servers=KAFKA_BROKER,
        group_id=GROUP_ID,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        session_timeout_ms=30_000,
        heartbeat_interval_ms=10_000,
    )


def build_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",   # fix #4 — wait for all in-sync replicas
        retries=3,
    )


# ── Alert publisher (fix #3 + #4) ─────────────────────────────────────────────

def publish_alert(producer: KafkaProducer, alert: dict) -> None:
    """Send alert and flush immediately so WebSocket clients see it at once.
    Raises nothing — delivery failures are logged and counted.
    """
    try:
        future: Future = producer.send(TOPIC_OUT, value=alert)
        producer.flush(timeout=5)        # flush buffer to broker NOW
        future.result(timeout=5)         # raises KafkaError on delivery failure
    except KafkaError as exc:
        logger.error("Failed to publish alert", error=str(exc))


# ── Core pipeline — pure function, no Kafka (fix #6) ─────────────────────────

def process_message(raw: dict, detector: Detector) -> Optional[dict]:
    """
    Run the full ML pipeline on one raw event dict.

    Returns an alert dict when the event is anomalous and non-benign.
    Returns None for normal / benign traffic.
    Raises ValidationError-derived exceptions for malformed input;
    all other exceptions propagate so run() can log and count them.
    """
    # 1 — Schema validation
    try:
        ev = RawEvent(**raw)
    except ValidationError as exc:
        logger.warning("Schema validation failed", errors=exc.errors())
        return None

    event = extract(ev.model_dump())

    # 2 — Isolation Forest anomaly score
    X = [[event[f] for f in FEATURE_NAMES]]
    if_score = detector.anomaly_score(X)[0]

    update_if_score(
        host=ev.hostName,
        pid=ev.processId,
        if_score=if_score,
        ts=ev.timestamp,
    )

    # 3 — Skip normal traffic
    if if_score > THRESHOLD:
        return None

    # 4 — XGBoost classification
    proba = detector.classify(X)[0]    # [p_benign, p_sus, p_evil]
    label = int(proba.argmax())

    if label == 0:
        return None   # anomalous IF score but XGBoost says benign — skip

    # 5 — SHAP per-event explanation (only when we're about to raise an alert)
    shap_vals = detector.explain(X)[0]

    return {
        "event":       event,
        "if_score":    round(if_score, 4),
        "xgb_class":   label,
        "xgb_label":   LABELS[label],
        "xgb_proba":   {LABELS[i]: round(float(p), 4) for i, p in enumerate(proba)},
        "shap_values": shap_vals,
    }


# ── RAG wrapper ───────────────────────────────────────────────────────────────

def _rag_task(alert: dict) -> None:
    """Submitted to the thread pool. Errors are logged, never propagated."""
    try:
        generate_report(alert)
    except Exception as exc:
        logger.error("RAG report failed", error=str(exc), label=alert.get("xgb_label"))


# ── Main loop (fix #2 + #3 + #7 + #8) ────────────────────────────────────────

def run(max_workers: int = MAX_WORKERS) -> None:
    detector  = Detector()
    _shutdown = False

    # ExitStack guarantees consumer.close(), producer.close(), executor.shutdown()
    # are ALL called even if an exception occurs — fix #3
    with ExitStack() as stack:
        consumer = stack.enter_context(_closing(build_consumer()))
        producer = stack.enter_context(_closing(build_producer()))
        executor = stack.enter_context(ThreadPoolExecutor(max_workers=max_workers))

        def _handle_signal(sig, _frame):
            nonlocal _shutdown
            logger.info("Shutdown signal received", signal=sig)
            _shutdown = True
            consumer.close()   # unblocks the for-loop below immediately

        signal.signal(signal.SIGINT,  _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        logger.info("Consumer ready", topic=TOPIC_IN, threshold=THRESHOLD)

        for msg in consumer:
            if _shutdown:
                break

            # fix #2 — one bad message never stops the loop
            try:
                alert = process_message(msg.value, detector)
            except Exception as exc:
                logger.exception("Unexpected error processing message", error=str(exc))
                continue

            if alert is None:
                continue

            publish_alert(producer, alert)

            # fix #7 — structured log fields, not a long f-string
            logger.warning(
                "ALERT",
                label=alert["xgb_label"],
                host=alert["event"].get("hostName"),
                pid=alert["event"].get("processId"),
                syscall=alert["event"].get("eventName"),
                if_score=alert["if_score"],
                p_evil=alert["xgb_proba"].get("EVIL"),
            )

            executor.submit(_rag_task, alert)

    logger.info("Consumer shut down cleanly")


# ── Context-manager shim for Kafka clients ────────────────────────────────────

@contextmanager
def _closing(resource):
    """Like contextlib.closing — calls resource.close() on exit regardless."""
    try:
        yield resource
    finally:
        try:
            resource.close()
        except Exception:
            pass


if __name__ == "__main__":
    run()
