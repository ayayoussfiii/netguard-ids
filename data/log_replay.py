"""
log_replay.py
─────────────
Streams BETH dataset rows into Kafka (raw.syscalls) at a configurable rate.
Simulates real-time eBPF sensor output from the 23 AWS honeypots.
Options:
    --speed INT     Events per second (-1 = max throughput). Default: $REPLAY_SPEED or 1000.
    --split STR     BETH split to replay: train | val | test | all. Default: all.
    --dry-run       Parse and count rows without publishing to Kafka.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path
from typing import Iterator

import numpy as np
import pandas as pd
from dotenv import load_dotenv
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable
from loguru import logger

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

BETH_DIR     = Path(os.getenv("BETH_DATA_DIR",       "data/beth/"))
KAFKA_BROKER = os.getenv("KAFKA_BROKER",              "localhost:9092")
TOPIC        = os.getenv("KAFKA_TOPIC_INPUT",         "raw.syscalls")
REPLAY_SPEED = int(os.getenv("REPLAY_SPEED",          "1000"))  # events/sec; -1 = max
LOG_INTERVAL = int(os.getenv("REPLAY_LOG_INTERVAL",   "10000"))
CSV_CHUNKSIZE = int(os.getenv("REPLAY_CSV_CHUNKSIZE", "50000"))

BETH_FILES: dict[str, str] = {
    "train": "labelled_training_data.csv",
    "val":   "labelled_validation_data.csv",
    "test":  "labelled_testing_data.csv",
}

# ── Graceful shutdown ─────────────────────────────────────────────────────────

_shutdown = False

def _handle_signal(sig, _frame) -> None:
    global _shutdown
    logger.warning("Signal {} received — stopping after current batch.", sig)
    _shutdown = True

signal.signal(signal.SIGINT,  _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ── JSON serialiser ───────────────────────────────────────────────────────────

def _json_default(obj: object) -> object:
    """Handle numpy scalars and other non-standard types explicitly."""
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON-serialisable")

# ── Kafka producer ────────────────────────────────────────────────────────────

def _on_send_error(exc: Exception) -> None:
    logger.error("Kafka delivery error: {}", exc)

def build_producer() -> KafkaProducer:
    try:
        producer = KafkaProducer(
            bootstrap_servers=KAFKA_BROKER,
            value_serializer=lambda v: json.dumps(v, default=_json_default).encode("utf-8"),
            acks="all",
            retries=5,
            retry_backoff_ms=200,
            compression_type="lz4",
        )
        logger.info("Kafka producer connected to {}", KAFKA_BROKER)
        return producer
    except NoBrokersAvailable as exc:
        logger.error("Cannot reach Kafka broker at {}: {}", KAFKA_BROKER, exc)
        raise SystemExit(1) from exc

# ── CSV loader ────────────────────────────────────────────────────────────────

def _iter_rows(path: Path) -> Iterator[dict]:
    """
    Yield rows from a BETH CSV as dicts, filling NaN with 0.
    Uses chunked reading to avoid loading the whole file into memory.
    """
    for chunk in pd.read_csv(path, chunksize=CSV_CHUNKSIZE):
        chunk.fillna(0, inplace=True)
        for _, row in chunk.iterrows():
            yield row.to_dict()

# ── Streaming ─────────────────────────────────────────────────────────────────

def stream_file(
    producer: KafkaProducer | None,
    path: Path,
    speed: int,
    *,
    dry_run: bool = False,
) -> int:
    """
    Stream a single BETH CSV into Kafka.

    Args:
        producer:  Connected KafkaProducer (must be None when dry_run=True).
        path:      Path to the CSV file.
        speed:     Target throughput in events/sec; -1 for max.
        dry_run:   If True, parse rows and count without publishing.

    Returns:
        Number of rows processed.
    """
    label   = "dry-run" if dry_run else TOPIC
    logger.info("Streaming {} → {}", path.name, label)

    interval = 1.0 / speed if speed > 0 else 0.0
    sent     = 0
    t_start  = time.monotonic()

    for event in _iter_rows(path):
        if _shutdown:
            logger.info("Shutdown requested — stopping stream.")
            break

        event["source_file"] = path.name
        event["replay_ts"]   = time.time()

        if not dry_run:
            producer.send(TOPIC, value=event).add_errback(_on_send_error)  # type: ignore[union-attr]

        sent += 1

        if sent % LOG_INTERVAL == 0:
            elapsed = time.monotonic() - t_start
            actual  = sent / elapsed if elapsed else float("inf")
            logger.info(
                "  {:>10,} events  |  {:.0f} ev/s  |  {}",
                sent, actual, path.name,
            )

        if interval:
            # Adaptive sleep: account for processing time already spent.
            target_ts = t_start + sent * interval
            slack      = target_ts - time.monotonic()
            if slack > 0:
                time.sleep(slack)

    if not dry_run:
        producer.flush()  # type: ignore[union-attr]

    elapsed = time.monotonic() - t_start
    logger.success(
        "Done — {:,} events from {} in {:.1f}s ({:.0f} ev/s)",
        sent, path.name, elapsed, sent / elapsed if elapsed else 0,
    )
    return sent

# ── CLI ───────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay BETH dataset rows into Kafka.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--speed", type=int, default=REPLAY_SPEED,
        help="Target events per second (-1 = max throughput).",
    )
    parser.add_argument(
        "--split", choices=[*BETH_FILES, "all"], default="all",
        help="BETH split(s) to replay.",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Parse rows and report counts without publishing to Kafka.",
    )
    return parser.parse_args()


def main() -> None:
    args     = _parse_args()
    producer = None if args.dry_run else build_producer()

    splits = list(BETH_FILES) if args.split == "all" else [args.split]
    total  = 0

    try:
        for split in splits:
            if _shutdown:
                break
            path = BETH_DIR / BETH_FILES[split]
            if not path.exists():
                logger.warning("File not found: {} — skipping", path)
                continue
            total += stream_file(producer, path, args.speed, dry_run=args.dry_run)
    finally:
        if producer is not None:
            producer.close()

    status = "Replay complete" if not _shutdown else "Replay interrupted"
    logger.success("{} — {:,} total events → [{}]", status, total, TOPIC)


if __name__ == "__main__":
    main()
