"""
consumer.py
───────────
Kafka consumer that orchestrates the full NetGuard pipeline:

  raw.syscalls  →  feature engineering  →  Isolation Forest
               →  XGBoost (if anomalous)  →  SHAP
               →  alerts.output  →  async RAG report
"""

import os
import json
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor

from kafka import KafkaConsumer, KafkaProducer
from loguru import logger
from dotenv import load_dotenv

from pipeline.features import extract, update_if_score, FEATURE_NAMES
from ml.detector import Detector
from rag.pipeline import generate_report

load_dotenv()

KAFKA_BROKER   = os.getenv("KAFKA_BROKER",        "localhost:9092")
TOPIC_IN       = os.getenv("KAFKA_TOPIC_INPUT",   "raw.syscalls")
TOPIC_OUT      = os.getenv("KAFKA_TOPIC_OUTPUT",  "alerts.output")
GROUP_ID       = os.getenv("KAFKA_GROUP_ID",      "netguard-consumer")
THRESHOLD      = float(os.getenv("ANOMALY_THRESHOLD", "-0.05"))


def build_consumer() -> KafkaConsumer:
    return KafkaConsumer(
        TOPIC_IN,
        bootstrap_servers=KAFKA_BROKER,
        group_id=GROUP_ID,
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        auto_offset_reset="earliest",
        enable_auto_commit=True,
    )


def build_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )


def publish_alert(producer: KafkaProducer, alert: dict):
    producer.send(TOPIC_OUT, value=alert)


def run(max_workers: int = 4):
    detector  = Detector()
    consumer  = build_consumer()
    producer  = build_producer()
    executor  = ThreadPoolExecutor(max_workers=max_workers)

    logger.info(f"Consumer ready — listening on [{TOPIC_IN}]")

    for msg in consumer:
        raw_event = msg.value

        # 1 — Feature engineering
        event = extract(raw_event)

        # 2 — Isolation Forest anomaly score
        X = [[event[f] for f in FEATURE_NAMES]]
        if_score = detector.anomaly_score(X)[0]

        # Update per-process IF score for parent propagation
        update_if_score(
            host=event.get("hostName", ""),
            pid=int(event.get("processId", 0)),
            if_score=if_score,
            ts=float(event.get("timestamp", 0)),
        )

        # 3 — Skip if score is below threshold (normal traffic)
        if if_score > THRESHOLD:
            continue

        # 4 — XGBoost classification
        proba  = detector.classify(X)[0]    # [p_benign, p_sus, p_evil]
        label  = int(proba.argmax())
        labels = ["benign", "SUS", "EVIL"]

        if label == 0:
            continue   # classified as benign — skip

        # 5 — SHAP per-event explanation
        shap_vals = detector.explain(X)[0]   # dict {feature: contribution}

        alert = {
            "event":       event,
            "if_score":    round(if_score, 4),
            "xgb_class":   label,
            "xgb_label":   labels[label],
            "xgb_proba":   {labels[i]: round(float(p), 4) for i, p in enumerate(proba)},
            "shap_values": shap_vals,
        }

        # 6 — Publish alert immediately (dashboard receives it via WebSocket)
        publish_alert(producer, alert)
        logger.warning(
            f"ALERT [{labels[label]}] — host={event.get('hostName')} "
            f"pid={event.get('processId')} syscall={event.get('eventName')} "
            f"IF={if_score:.3f} p_evil={proba[2]:.3f}"
        )

        # 7 — Async RAG report (non-blocking)
        executor.submit(generate_report, alert)


if __name__ == "__main__":
    run()
