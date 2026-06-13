"""
──────────
Downloads and indexes the MITRE ATT&CK Enterprise matrix into ChromaDB.
Run once before starting the pipeline:

    python rag/indexer.py [--force]

Options:
    --force   Re-index even if the collection already exists.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
import urllib.error
from typing import Iterator

import chromadb
from chromadb.utils import embedding_functions
from dotenv import load_dotenv
from loguru import logger

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

CHROMA_DIR      = os.getenv("CHROMA_PERSIST_DIR",  "rag/chroma_store/")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL",      "sentence-transformers/all-MiniLM-L6-v2")
COLLECTION_NAME = "mitre_attack"
BATCH_SIZE      = int(os.getenv("INDEXER_BATCH_SIZE", "64"))
MAX_DESC_CHARS  = int(os.getenv("INDEXER_MAX_DESC_CHARS", "2000"))

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# ── Fetch ─────────────────────────────────────────────────────────────────────

def fetch_attack_matrix() -> dict:
    """Download the MITRE ATT&CK Enterprise STIX bundle."""
    logger.info("Fetching MITRE ATT&CK Enterprise matrix from {}", ATTACK_URL)
    try:
        with urllib.request.urlopen(ATTACK_URL, timeout=60) as response:
            data = json.loads(response.read().decode())
    except urllib.error.URLError as exc:
        logger.error("Network error while fetching ATT&CK matrix: {}", exc)
        raise SystemExit(1) from exc
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse ATT&CK JSON: {}", exc)
        raise SystemExit(1) from exc

    logger.success("{:,} STIX objects fetched", len(data.get("objects", [])))
    return data


# ── Extract ───────────────────────────────────────────────────────────────────

def _first_mitre_ref(refs: list[dict], field: str) -> str:
    return next(
        (r[field] for r in refs if r.get("source_name") == "mitre-attack" and field in r),
        "",
    )


def extract_techniques(data: dict) -> list[dict]:
    """
    Yield active attack-pattern objects (techniques & sub-techniques)
    from the STIX bundle, skipping deprecated entries.
    """
    techniques = []
    skipped    = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            skipped += 1
            continue

        ext = obj.get("external_references", [])
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
        ]

        techniques.append({
            "id":           obj["id"],
            "technique_id": _first_mitre_ref(ext, "external_id"),
            "name":         obj.get("name", ""),
            "description":  obj.get("description", "")[:MAX_DESC_CHARS],
            "tactics":      ", ".join(tactics),
            "url":          _first_mitre_ref(ext, "url"),
            "platforms":    ", ".join(obj.get("x_mitre_platforms", [])),
            "is_subtechnique": obj.get("x_mitre_is_subtechnique", False),
        })

    logger.info(
        "{} active techniques extracted ({} deprecated/revoked skipped)",
        len(techniques), skipped,
    )
    return techniques


# ── Document builder ──────────────────────────────────────────────────────────

def build_document(t: dict) -> str:
    """Construct the text chunk that will be embedded for *t*."""
    return (
        f"Technique: {t['technique_id']} — {t['name']}\n"
        f"Tactics: {t['tactics']}\n"
        f"Platforms: {t['platforms']}\n"
        f"Description: {t['description']}"
    )


# ── Batch helper ──────────────────────────────────────────────────────────────

def _batched(items: list, size: int) -> Iterator[list]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


# ── Index ─────────────────────────────────────────────────────────────────────

def index_techniques(techniques: list[dict], *, force: bool = False) -> None:
    """Upsert *techniques* into ChromaDB. Re-creates the collection when *force* is True."""
    if not techniques:
        logger.warning("No techniques to index — aborting.")
        return

    logger.info("Connecting to ChromaDB at {}", CHROMA_DIR)
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    existing = {c.name for c in client.list_collections()}

    if COLLECTION_NAME in existing:
        if force:
            client.delete_collection(COLLECTION_NAME)
            logger.info("Existing collection '{}' dropped (--force)", COLLECTION_NAME)
        else:
            logger.info(
                "Collection '{}' already exists — skipping indexing. "
                "Pass --force to re-index.",
                COLLECTION_NAME,
            )
            return

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    total = len(techniques)
    logger.info("Indexing {} techniques in batches of {} …", total, BATCH_SIZE)

    for batch in _batched(techniques, BATCH_SIZE):
        collection.add(
            ids       =[t["id"]           for t in batch],
            documents =[build_document(t) for t in batch],
            metadatas =[
                {
                    "technique_id":   t["technique_id"],
                    "name":           t["name"],
                    "tactics":        t["tactics"],
                    "url":            t["url"],
                    "is_subtechnique": t["is_subtechnique"],
                }
                for t in batch
            ],
        )

    logger.success(
        "ChromaDB collection '{}' ready — {} techniques at {}",
        COLLECTION_NAME, total, CHROMA_DIR,
    )


# ── Entry point ───────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Index the MITRE ATT&CK Enterprise matrix into ChromaDB."
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Drop and re-create the collection if it already exists.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args       = _parse_args()
    data       = fetch_attack_matrix()
    techniques = extract_techniques(data)
    index_techniques(techniques, force=args.force)
