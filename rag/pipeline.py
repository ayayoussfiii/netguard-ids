"""

───────────
RAG pipeline: retrieves MITRE ATT&CK techniques relevant to an alert,
then prompts an LLM to generate a structured incident report.

Called asynchronously from pipeline/consumer.py after an alert is published.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional

import chromadb
from chromadb.utils import embedding_functions
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from loguru import logger
from dotenv import load_dotenv

load_dotenv()

# ── Configuration ─────────────────────────────────────────────────────────────

CHROMA_DIR      = os.getenv("CHROMA_PERSIST_DIR",  "rag/chroma_store/")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL",      "sentence-transformers/all-MiniLM-L6-v2")
COLLECTION_NAME = "mitre_attack"
TOP_K           = int(os.getenv("RAG_TOP_K",        "5"))
LLM_PROVIDER    = os.getenv("LLM_PROVIDER",         "openai")
MAX_DOC_CHARS   = int(os.getenv("RAG_MAX_DOC_CHARS", "400"))
MAX_SHAP_FEATS  = int(os.getenv("RAG_MAX_SHAP_FEATS", "8"))

# ── LLM setup ─────────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_llm():
    """Instantiate and cache the LLM (once per process)."""
    if LLM_PROVIDER == "openai":
        return ChatOpenAI(
            model="gpt-4o-mini",
            temperature=0,    # deterministic, auditable reports
            max_tokens=1024,
        )
    if LLM_PROVIDER == "ollama":
        from langchain_community.llms import Ollama  # optional dependency
        return Ollama(
            base_url=os.getenv("OLLAMA_BASE_URL", "http://localhost:11434"),
            model=os.getenv("OLLAMA_MODEL", "llama3"),
            temperature=0,
        )
    raise ValueError(
        f"Unknown LLM_PROVIDER: {LLM_PROVIDER!r}. "
        "Supported values: 'openai', 'ollama'."
    )


# ── ChromaDB retriever ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _get_collection():
    """Open (and cache) the ChromaDB collection."""
    ef = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL
    )
    client = chromadb.PersistentClient(path=CHROMA_DIR)
    return client.get_collection(name=COLLECTION_NAME, embedding_function=ef)


def retrieve_techniques(query: str) -> list[dict]:
    """Return the top-K MITRE ATT&CK techniques most similar to *query*."""
    results = _get_collection().query(
        query_texts=[query],
        n_results=TOP_K,
        include=["documents", "distances", "metadatas"],
    )
    return [
        {
            "document":   doc,
            "metadata":   meta,
            "similarity": round(1 - dist, 4),
        }
        for doc, meta, dist in zip(
            results["documents"][0],
            results["metadatas"][0],
            results["distances"][0],
        )
    ]


# ── Prompt templates ──────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are a senior threat analyst. You receive:
1. A security alert from a host-based IDS (BETH dataset — real AWS honeypot syscall data)
2. The top SHAP features that triggered the alert
3. Relevant MITRE ATT&CK techniques retrieved from a vector database

Your task: produce a structured JSON incident report.
Respond ONLY with valid JSON — no preamble, no markdown fences, no explanation.

JSON schema:
{
  "technique_id":      "string — ATT&CK technique ID (e.g. T1059.004)",
  "technique_name":    "string — technique name",
  "tactic":            "string — ATT&CK tactic (e.g. Execution)",
  "kill_chain_phase":  "string — kill chain phase",
  "confidence":        float between 0 and 1,
  "triggered_by": {
    "eventName":          "string",
    "processName":        "string",
    "parentProcessName":  "string",
    "top_shap_features":  [{"feature": "string", "contribution": float}]
  },
  "recommendation":    "string — 2-4 sentence actionable remediation",
  "references":        ["list of ATT&CK URLs"]
}
"""

USER_TEMPLATE = """\
## Alert

- Host:      {host}
- Syscall:   {event_name}
- Process:   {process_name}  (PID {pid})
- Parent:    {parent_process_name}  (PPID {ppid})
- IF score:  {if_score}
- XGB class: {xgb_label}  (p_evil={p_evil})
- Timestamp: {timestamp}

## Top SHAP features (descending importance)

{shap_table}

## Retrieved MITRE ATT&CK techniques

{techniques_text}
"""

_PROMPT_CHAIN = (
    ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human",  "{input}"),
    ])
    | None  # placeholder; replaced lazily in generate_report
    | JsonOutputParser()
)


# ── Formatting helpers ────────────────────────────────────────────────────────

def _build_query(alert: dict) -> str:
    ev   = alert.get("event", {})
    shap = alert.get("shap_values", {})
    top_features = ", ".join(list(shap.keys())[:5])
    return (
        f"syscall {ev.get('eventName', '')} "
        f"process {ev.get('processName', '')} "
        f"parent {ev.get('parentProcessName') or ev.get('processName', '')} "
        f"anomalous features: {top_features}"
    )


def _format_shap(shap_values: dict) -> str:
    lines = []
    for feat, val in list(shap_values.items())[:MAX_SHAP_FEATS]:
        bar  = "▓" * max(1, int(abs(val) * 20))
        sign = "+" if val >= 0 else "-"
        lines.append(f"  {sign}{abs(val):.5f}  {bar}  {feat}")
    return "\n".join(lines) if lines else "  (no SHAP values)"


def _format_techniques(techniques: list[dict]) -> str:
    blocks = []
    for i, t in enumerate(techniques, 1):
        meta = t["metadata"]
        snippet = t["document"][:MAX_DOC_CHARS].rstrip()
        blocks.append(
            f"[{i}] {meta.get('technique_id', 'N/A')} — {meta.get('name', 'N/A')}\n"
            f"    Tactic:     {meta.get('tactics', 'N/A')}\n"
            f"    Similarity: {t['similarity']:.3f}\n"
            f"    {snippet}…"
        )
    return "\n\n".join(blocks) if blocks else "(no techniques retrieved)"


def _build_user_message(alert: dict) -> str:
    ev    = alert.get("event", {})
    shap  = alert.get("shap_values", {})
    proba = alert.get("xgb_proba", {})

    return USER_TEMPLATE.format(
        host                = ev.get("hostName",          "unknown"),
        event_name          = ev.get("eventName",         "unknown"),
        process_name        = ev.get("processName",       "unknown"),
        pid                 = ev.get("processId",         "?"),
        parent_process_name = ev.get("parentProcessName") or ev.get("processName", "unknown"),
        ppid                = ev.get("parentProcessId",   "?"),
        if_score            = alert.get("if_score",       "?"),
        xgb_label           = alert.get("xgb_label",     "?"),
        p_evil              = proba.get("EVIL",           "?"),
        timestamp           = ev.get("timestamp",         "?"),
        shap_table          = _format_shap(shap),
        techniques_text     = _format_techniques(retrieve_techniques(_build_query(alert))),
    )


# ── Public API ────────────────────────────────────────────────────────────────

def generate_report(alert: dict) -> Optional[dict]:
    """
    Generate a MITRE ATT&CK incident report for the given alert.
    Called asynchronously from consumer.py.

    Returns the parsed report dict, or None on failure.
    """
    try:
        user_msg = _build_user_message(alert)

        prompt = ChatPromptTemplate.from_messages([
            ("system", SYSTEM_PROMPT),
            ("human",  "{input}"),
        ])
        chain  = prompt | _get_llm() | JsonOutputParser()
        report = chain.invoke({"input": user_msg})

        logger.info(
            "RAG report generated: {} — {} (confidence={})",
            report.get("technique_id"),
            report.get("technique_name"),
            report.get("confidence"),
        )
        return report

    except Exception as exc:
        logger.exception("RAG pipeline failed: {}", exc)
        return None
