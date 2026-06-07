"""
producer.py
───────────
Kafka producer wrapper. Used by log_replay.py and unit tests.
"""

import json
import os
from kafka import KafkaProducer
from dotenv import load_dotenv

load_dotenv()

KAFKA_BROKER = os.getenv("KAFKA_BROKER", "localhost:9092")
TOPIC        = os.getenv("KAFKA_TOPIC_INPUT", "raw.syscalls")


def get_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BROKER,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        acks="all",
        retries=5,
        linger_ms=5,        # micro-batching for throughput
        batch_size=32768,
    )
