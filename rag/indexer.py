
"""
Downloads and indexes the MITRE ATT&CK Enterprise matrix into ChromaDB.
Run once before starting the pipeline.
    python rag/indexer.py
"""

import os
import json
import urllib.request
from pathlib import Path

import chromadb
from chromadb.utils import embedding_functions
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

CHROMA_DIR      = os.getenv("CHROMA_PERSIST_DIR", "rag/chroma_store/")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "sentence-transformers/all-MiniLM-L6-v2")
COLLECTION_NAME = "mitre_attack"

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)


def fetch_attack_matrix() -> dict:
    logger.info("Fetching MITRE ATT&CK Enterprise matrix...")
    with urllib.request.urlopen(ATTACK_URL) as r:
        data = json.loads(r.read().decode())
    logger.success(f"  {len(data['objects']):,} objects fetched")
    return data


def extract_techniques(data: dict) -> list[dict]:
    """Extract attack-pattern objects (techniques) from the STIX bundle."""
    techniques = []
    for obj in data["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("x_mitre_deprecated", False):
            continue

        ext = obj.get("external_references", [])
        tid  = next((r["external_id"] for r in ext
                     if r.get("source_name") == "mitre-attack"), "")
        url  = next((r["url"] for r in ext
                     if r.get("source_name") == "mitre-attack"), "")

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
        ]

        techniques.append({
            "id":          obj["id"],
            "technique_id": tid,
            "name":        obj.get("name", ""),
            "description": obj.get("description", "")[:2000],
            "tactics":     ", ".join(tactics),
            "url":         url,
            "platforms":   ", ".join(obj.get("x_mitre_platforms", [])),
        })

    logger.info(f"  {len(techniques)} active techniques extracted")
    return techniques


def build_document(t: dict) -> str:
    """Build a rich text document for embedding."""
    return (
        f"Technique: {t['technique_id']} — {t['name']}\n"
        f"Tactics: {t['tactics']}\n"
        f"Platforms: {t['platforms']}\n"
        f"Description: {t['description']}"
    )


def index_techniques(techniques: list[dict]):
    logger.info(f"Indexing {len(techniques)} techniques into ChromaDB...")

    client = chromadb.PersistentClient(path=CHROMA_DIR)

    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )

    # Drop existing collection to allow re-indexing
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass

    collection = client.create_collection(
        name=COLLECTION_NAME,
        embedding_function=ef,
        metadata={"hnsw:space": "cosine"},
    )

    batch_size = 64
    for i in range(0, len(techniques), batch_size):
        batch = techniques[i : i + batch_size]
        collection.add(
            ids       =[t["id"] for t in batch],
            documents =[build_document(t) for t in batch],
            metadatas =[{
                "technique_id": t["technique_id"],
                "name":         t["name"],
                "tactics":      t["tactics"],
                "url":          t["url"],
            } for t in batch],
        )
        logger.info(f"  Indexed {min(i + batch_size, len(techniques))}/{len(techniques)}")

    logger.success(f"ChromaDB collection [{COLLECTION_NAME}] ready at {CHROMA_DIR}")


if __name__ == "__main__":
    data       = fetch_attack_matrix()
    techniques = extract_techniques(data)
    index_techniques(techniques)
