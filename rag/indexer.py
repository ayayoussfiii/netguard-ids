"""Downloads and indexes the MITRE ATT&CK Enterprise matrix into ChromaDB.

Run once before starting the pipeline:

    python rag/indexer.py [--force]

Options:
    --force   Re-index even if the collection already exists.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
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
FETCH_RETRIES   = int(os.getenv("INDEXER_FETCH_RETRIES", "3"))
FETCH_BACKOFF   = float(os.getenv("INDEXER_FETCH_BACKOFF", "2.0"))

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)

# Regex patterns for description cleaning
_CITATION_RE = re.compile(r"\(Citation:[^)]+\)")
_MD_BOLD_RE  = re.compile(r"\*{1,2}([^*]+)\*{1,2}")
_WHITESPACE_RE = re.compile(r"\s{2,}")


# ── Text helpers ──────────────────────────────────────────────────────────────

def _clean_description(text: str) -> str:
    """
    Strip Markdown artefacts and inline citations from ATT&CK descriptions.
    These pollute embedding space without adding retrieval value.
    """
    text = _CITATION_RE.sub("", text)       # remove (Citation: ...)
    text = _MD_BOLD_RE.sub(r"\1", text)     # unwrap **bold** / *italic*
    text = _WHITESPACE_RE.sub(" ", text)    # normalise whitespace
    return text.strip()


def _truncate(text: str, max_chars: int) -> str:
    """Truncate *text* to *max_chars*, breaking on a word boundary."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rsplit(" ", 1)[0] + " …"


# ── Fetch ─────────────────────────────────────────────────────────────────────

def fetch_attack_matrix(
    retries: int = FETCH_RETRIES,
    backoff: float = FETCH_BACKOFF,
) -> dict:
    """
    Download the MITRE ATT&CK Enterprise STIX bundle.
    Retries up to *retries* times with exponential back-off.
    """
    logger.info("Fetching MITRE ATT&CK Enterprise matrix from {}", ATTACK_URL)

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(ATTACK_URL, timeout=60) as response:
                data = json.loads(response.read().decode())
            break  # success
        except urllib.error.URLError as exc:
            if attempt == retries:
                logger.error("Network error after {} attempts: {}", retries, exc)
                raise SystemExit(1) from exc
            wait = backoff ** attempt
            logger.warning(
                "Attempt {}/{} failed — retrying in {:.0f}s ({})",
                attempt, retries, wait, exc,
            )
            time.sleep(wait)
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse ATT&CK JSON: {}", exc)
            raise SystemExit(1) from exc

    # Validate STIX bundle structure
    if data.get("type") != "bundle" or "objects" not in data:
        logger.error(
            "Unexpected payload — not a STIX bundle. Keys found: {}",
            list(data.keys()),
        )
        raise SystemExit(1)

    logger.success("{:,} STIX objects fetched", len(data["objects"]))
    return data


# ── Extract ───────────────────────────────────────────────────────────────────

def _first_mitre_ref(refs: list[dict], field: str) -> str:
    return next(
        (r[field] for r in refs if r.get("source_name") == "mitre-attack" and field in r),
        "",
    )


def extract_techniques(data: dict) -> list[dict]:
    """
    Return active attack-pattern objects (techniques & sub-techniques)
    from the STIX bundle, skipping deprecated/revoked entries.
    """
    techniques: list[dict] = []
    skipped = 0

    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False) or obj.get("revoked", False):
            skipped += 1
            continue

        ext     = obj.get("external_references", [])
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        desc    = _truncate(_clean_description(obj.get("description", "")), MAX_DESC_CHARS)

        techniques.append({
            "id":             obj["id"],
            "technique_id":   _first_mitre_ref(ext, "external_id"),
            "name":           obj.get("name", ""),
            "description":    desc,
            "tactics":        ", ".join(tactics),
            "url":            _first_mitre_ref(ext, "url"),
            "platforms":      ", ".join(obj.get("x_mitre_platforms", [])),
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
    """
    Upsert *techniques* into ChromaDB.

    Behaviour:
    - If the collection exists and is non-empty, skip (unless *force*).
    - If the collection exists but is empty, re-index automatically.
    - If *force* is True, drop and recreate the collection.
    """
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
            col   = client.get_collection(COLLECTION_NAME, embedding_function=ef)
            count = col.count()
            if count > 0:
                logger.info(
                    "Collection '{}' already contains {:,} docs — skipping. "
                    "Pass --force to re-index.",
                    COLLECTION_NAME, count,
                )
                return
            # Collection exists but is empty — drop and re-create
            logger.warning(
                "Collection '{}' exists but is empty — re-indexing.", COLLECTION_NAME
            )
            client.delete_collection(COLLECTION_NAME)

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    total   = len(techniques)
    indexed = 0
    logger.info("Indexing {} techniques in batches of {} …", total, BATCH_SIZE)

    for batch in _batched(techniques, BATCH_SIZE):
        collection.add(
            ids=[t["id"] for t in batch],
            documents=[build_document(t) for t in batch],
            metadatas=[
                {
                    "technique_id":    t["technique_id"],
                    "name":            t["name"],
                    "tactics":         t["tactics"],
                    "platforms":       t["platforms"],
                    "url":             t["url"],
                    "is_subtechnique": t["is_subtechnique"],
                    # Short excerpt for display without re-fetching
                    "description":     t["description"][:500],
                }
                for t in batch
            ],
        )
        indexed += len(batch)
        logger.info(
            "  Progress: {}/{} ({:.0f}%)",
            indexed, total, indexed / total * 100,
        )

    logger.success(
        "ChromaDB collection '{}' ready — {:,} techniques at {}",
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
    sys.exit(0)
