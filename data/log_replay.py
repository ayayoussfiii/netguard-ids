"""
log_replay.py
─────────────
Streams BETH dataset rows into Kafka (raw.syscalls) at a configurable rate.
Simulates real-time eBPF sensor output from the 23 AWS honeypots.

Usage:
    python data/log_replay.py [--speed 1000] [--host 0]
"""

import os
import json
import time
import argparse
import glob
from pathlib import Path

import pandas as pd
from kafka import KafkaProducer
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

BETH_DIR     = Path(os.getenv("BETH_DATA_DIR", "data/beth/"))
KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
TOPIC        = os.getenv("KAFKA_TOPIC_INPUT", "raw.syscalls")
REPLAY_SPEED = int(os.getenv("REPLAY_SPEED", 1000))   # events/sec; -1 = max

BETH_FILES = {
    "train": "labelled_training_data.csv",
    "val":   "labelled_validation_data.csv",
    "test":  "labelled_testing_data.csv",
}


def build_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=5,
    )


def stream_file(producer: KafkaProducer, path: Path, speed: int) -> int:
    """Stream a single BETH CSV into Kafka. Returns number of rows sent."""
    logger.info(f"Streaming {path.name}  →  {TOPIC}")
    df = pd.read_csv(path)
    df = df.fillna(0)

    interval = 1.0 / speed if speed > 0 else 0
    sent = 0

    for _, row in df.iterrows():
        event = row.to_dict()
        event["source_file"] = path.name
        event["replay_ts"]   = time.time()

        producer.send(TOPIC, value=event)
        sent += 1

        if sent % 10_000 == 0:
            logger.info(f"  {sent:,} events sent from {path.name}")

        if interval:
            time.sleep(interval)

    producer.flush()
    logger.success(f"  Done — {sent:,} events from {path.name}")
    return sent


def main():
    parser = argparse.ArgumentParser(description="BETH → Kafka replay")
    parser.add_argument("--speed", type=int, default=REPLAY_SPEED,
                        help="Events per second (-1 = max)")
    parser.add_argument("--split", choices=["train", "val", "test", "all"],
                        default="all", help="Which BETH split to replay")
    args = parser.parse_args()

    producer = build_producer()
    total    = 0

    splits = list(BETH_FILES.keys()) if args.split == "all" else [args.split]

    for split in splits:
        path = BETH_DIR / BETH_FILES[split]
        if not path.exists():
            logger.warning(f"File not found: {path} — skipping")
            continue
        total += stream_file(producer, path, args.speed)

    logger.success(f"Replay complete — {total:,} total events sent to [{TOPIC}]")


if __name__ == "__main__":
    main()
