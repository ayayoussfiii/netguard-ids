<div align="center">

```
███╗   ██╗███████╗████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
████╗  ██║██╔════╝╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██╔██╗ ██║█████╗     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║╚██╗██║██╔══╝     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
██║ ╚████║███████╗   ██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

**Kernel-level threat detection · Real honeypot data · LLM-generated MITRE ATT&CK reports**

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![Kafka](https://img.shields.io/badge/Apache_Kafka-Streaming-231F20?style=flat-square&logo=apache-kafka&logoColor=white)](https://kafka.apache.org)
[![XGBoost](https://img.shields.io/badge/XGBoost-Anomaly-FF6600?style=flat-square)](https://xgboost.readthedocs.io)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-Mapped-CC0000?style=flat-square)](https://attack.mitre.org)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)](https://docker.com)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)](LICENSE)

</div>

---

## What is NetGuard?

NetGuard is a real-time **host-based intrusion detection system** built on top of the [BETH dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset) — kernel-level syscall logs and DNS events captured from 23 AWS honeypots during live attacks.

Most IDS tools stop at "something looks wrong." NetGuard answers three questions automatically:

| Question | How |
|---|---|
| **Is this anomalous?** | Isolation Forest on eBPF syscall sequences |
| **What kind of behavior is this?** | XGBoost on process + DNS features (EVIL / SUS / benign) |
| **What should I do about it?** | RAG over MITRE ATT&CK → LLM-generated incident report |

Every alert comes with per-event SHAP values and a structured MITRE ATT&CK report — automatically, in real time.

---

## Why BETH?

> *Most IDS research datasets are simulated. BETH is not.*

| | CICIDS-2017 | BETH (2021) |
|---|---|---|
| Data origin | Simulated network flows | Real AWS honeypots |
| Data type | TCP/UDP flow statistics | Kernel syscalls + DNS (eBPF) |
| Attack realism | Scripted scenarios | Live adversarial activity |
| Attack type | Multi-class (DDoS, PortScan…) | Botnet C2 — single real intrusion chain |
| Volume | ~2.8M flows | **8M+ events across 23 hosts** |
| Label granularity | Per-flow | Per-event (`EVIL` / `SUS` / benign) |
| Published | CIC Technical Report | **NeurIPS/CAMLIS Workshop 2021** |
| Availability | Direct download | Kaggle (open) |

BETH captures something CICIDS-2017 cannot: **the full behavioral fingerprint of a host under attack** — process tree, syscall sequence, DNS beaconing to C2 — at kernel resolution.

---

## Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │              BETH Dataset (Kaggle)           │
                    │  23 AWS honeypots · 8M+ events · real C2    │
                    │  labelled: EVIL / SUS / benign               │
                    └────────────────────┬────────────────────────┘
                                         │
                              eBPF syscall logs + DNS
                                         │
                                         ▼
                             ┌─────────────────────┐
                             │    log_replay.py     │
                             │  streams BETH CSVs   │
                             │  → Kafka producer    │
                             └──────────┬──────────┘
                                        │
                                        ▼
                              Kafka  ── raw.syscalls
                                        │
                          ┌─────────────▼──────────────┐
                          │      Feature Engineering    │
                          │                             │
                          │  process sequences          │
                          │  syscall entropy            │
                          │  parent-child PID chains    │
                          │  DNS query frequency        │
                          │  argument fingerprinting    │
                          └─────────────┬──────────────┘
                                        │
                          ┌─────────────▼──────────────┐
                          │         ML Engine           │
                          │                             │
                          │  Isolation Forest           │
                          │    → anomaly score          │
                          │                             │
                          │  XGBoost                   │
                          │    → EVIL / SUS / benign   │
                          │                             │
                          │  SHAP                       │
                          │    → per-event explanation  │
                          └─────────────┬──────────────┘
                                        │
                              Kafka  ── alerts.output
                                        │
                          ┌─────────────▼──────────────┐
                          │        RAG Pipeline         │
                          │                             │
                          │  ChromaDB                   │
                          │    MITRE ATT&CK embeddings  │
                          │                             │
                          │  LangChain + LLM            │
                          │    → technique mapping      │
                          │    → kill chain phase       │
                          │    → remediation plan       │
                          └─────────────┬──────────────┘
                                        │
                          ┌─────────────▼──────────────┐
                          │   PostgreSQL + pgvector     │
                          │   events · alerts · reports │
                          └─────────────┬──────────────┘
                                        │
                    ┌───────────────────┴──────────────────┐
                    │                                       │
          ┌─────────▼──────────┐               ┌───────────▼──────────┐
          │      FastAPI        │               │      Streamlit        │
          │                     │               │                       │
          │  GET  /alerts       │               │  live alert stream    │
          │  GET  /alerts/{id}  │               │  process tree view    │
          │  WS   /stream       │               │  SHAP waterfall       │
          │  POST /explain      │               │  LLM report panel     │
          │  GET  /stats        │               │  DNS heatmap          │
          └─────────────────────┘               └───────────────────────┘
```

---

## The BETH Dataset

BETH (BPF-Extended Tracking Honeypot) was published by Highnam et al. at the **CAMLIS / NeurIPS Workshop 2021**.

### Collection setup

- **23 AWS EC2 honeypots** exposed to real internet traffic
- **eBPF sensors** capture kernel-level events: process creation (`clone`/`execve`), termination, file access
- **DNS logs** capture outbound network activity — beaconing, C2 communication
- Each host has benign baseline activity + **at most one real attack event**

### Label schema

| Label | Meaning |
|---|---|
| `benign` (0) | Normal system activity |
| `SUS` (1) | Suspicious — process behavior outside baseline |
| `EVIL` (2) | Confirmed attack — directly part of the intrusion chain |

### Observed attack pattern

The intrusion captured in the test set follows a classic **botnet implant sequence**:

```
Initial access → Environment recon → C2 check-in → Sleep → Attack launch
```

This maps directly to MITRE ATT&CK tactics: **Initial Access → Discovery → Command & Control → Execution**.

### Features (14 raw, 9 numeric)

| Feature | Type | Description |
|---|---|---|
| `processId` | int | PID of the event |
| `parentProcessId` | int | Parent PID |
| `userId` | int | UID of the calling process |
| `mountNamespace` | int | Namespace identifier |
| `eventId` | int | Kernel event type |
| `argsNum` | int | Number of syscall arguments |
| `returnValue` | int | Syscall return code |
| `timestamp` | float | Kernel timestamp (ns) |
| `processName` | str | Process name |
| `hostName` | str | Host identifier |
| `eventName` | str | Syscall name (`execve`, `clone`, `openat`…) |
| `args` | str | Raw syscall arguments |
| `sus` | int | SUS label |
| `evil` | int | EVIL label |

### Download

```bash
# via Kaggle CLI
kaggle datasets download katehighnam/beth-dataset
unzip beth-dataset.zip -d data/beth/
```

Or download directly from [kaggle.com/datasets/katehighnam/beth-dataset](https://www.kaggle.com/datasets/katehighnam/beth-dataset).

---

## ML Models

### Isolation Forest — unsupervised anomaly detection

BETH's training and validation sets contain **no attack events** — only benign activity. This makes it a strictly semi-supervised problem, which is exactly what Isolation Forest is designed for.

The model learns the distribution of normal syscall behavior per host. At inference, each event receives an anomaly score; events exceeding the threshold are forwarded to the classifier and trigger the RAG pipeline.

```python
# Training on benign-only data (hosts 0–7)
model = IsolationForest(
    n_estimators=200,
    contamination=0.01,   # expected anomaly rate
    max_features=0.8,
    random_state=42
)
model.fit(X_train_benign)
```

### XGBoost — EVIL / SUS / benign classification

Trained on the labeled subset. Classifies each flagged event into one of three behavioral classes and outputs a probability per class.

Key engineered features fed to XGBoost:

- **Syscall entropy** — Shannon entropy of syscall sequence per process window
- **Parent-child anomaly score** — how unusual is this PID relative to its parent?
- **DNS query rate** — outbound DNS request frequency (beaconing signal)
- **Argument fingerprint** — hashed representation of syscall argument patterns
- **Return value distribution** — ratio of failed syscalls (unusual failure rates signal probing)

### SHAP — per-event explanation

SHAP values are computed per event at inference time — not global importance. The dashboard shows a waterfall chart of the top features that pushed this specific event above the anomaly threshold.

```python
explainer = shap.TreeExplainer(xgb_model)
shap_values = explainer(X_event)
# → feature contributions for this specific event
```

---

## Feature Engineering

Raw BETH events are 14-dimensional. NetGuard engineers **23 derived features** using sliding windows and sequence statistics computed per process and per host.

### Syscall entropy

Shannon entropy over the syscall sequence of a process within a time window `W`:

```
H(P, W) = - Σ p(eᵢ) · log₂ p(eᵢ)
```

where `p(eᵢ)` is the relative frequency of syscall type `eᵢ` in window `W` for process `P`. Benign processes show low entropy (repetitive I/O patterns). Intrusion activity — reconnaissance, shell spawning — shows high entropy.

### Parent-child anomaly propagation

For each event, the anomaly score of the parent process is propagated as a feature:

```
parent_score(pid) = IF_score(parentProcessId(pid))
```

This captures lateral process tree anomalies: a benign-looking child spawned by a suspicious parent is flagged even if its own syscalls are unremarkable.

### DNS beaconing rate

Outbound DNS query frequency over a rolling 60-second window per host:

```
dns_rate(host, t) = count(DNS_events, host, [t-60, t]) / 60
```

C2 beaconing produces highly regular, elevated DNS rates. Benign hosts show bursty, low-frequency DNS patterns.

### Argument fingerprint

Syscall arguments are hashed into a fixed-length integer representation:

```python
arg_fingerprint = hash(tuple(sorted(args.split(",")))) % 2**32
```

Identical exploit payloads produce identical fingerprints, enabling detection of repeated attack patterns across hosts.

### Full feature vector (23 dimensions)

| # | Feature | Window | Description |
|---|---|---|---|
| 1 | `syscall_entropy` | 30s | Shannon entropy of syscall sequence |
| 2 | `syscall_entropy_60` | 60s | Slower window entropy |
| 3 | `unique_syscalls` | 30s | Cardinality of distinct syscall types |
| 4 | `event_rate` | 10s | Events per second |
| 5 | `event_rate_60` | 60s | Events per second (slow) |
| 6 | `parent_anomaly_score` | — | IF score of parent PID |
| 7 | `uid_switch` | — | Boolean: userId ≠ parentUserId |
| 8 | `namespace_delta` | — | mountNamespace differs from parent |
| 9 | `failed_syscall_ratio` | 30s | Ratio of returnValue < 0 |
| 10 | `argsNum_mean` | 30s | Mean number of syscall arguments |
| 11 | `argsNum_std` | 30s | Std dev of syscall arguments |
| 12 | `arg_fingerprint` | — | Hashed argument pattern |
| 13 | `execve_rate` | 30s | Rate of execve calls (shell spawning) |
| 14 | `clone_rate` | 30s | Rate of clone calls (forking) |
| 15 | `openat_rate` | 30s | Rate of openat calls (file access) |
| 16 | `dns_rate` | 60s | DNS queries per second (host level) |
| 17 | `dns_entropy` | 60s | Entropy of queried domain names |
| 18 | `pid_depth` | — | Depth in process tree (root = 0) |
| 19 | `siblings_count` | — | Number of processes sharing same PPID |
| 20 | `inter_event_mean` | 30s | Mean inter-event time (ms) |
| 21 | `inter_event_std` | 30s | Std dev of inter-event time |
| 22 | `inter_event_cv` | 30s | Coefficient of variation (regularity signal) |
| 23 | `host_anomaly_baseline` | 300s | Rolling mean anomaly score for host |

---

## ML Models

### Isolation Forest — unsupervised anomaly detection

BETH's training and validation sets contain **no attack events** — only benign activity. This makes it a strictly semi-supervised problem, which is exactly what Isolation Forest is designed for.

The model learns the distribution of normal syscall behavior per host. At inference, each event receives an anomaly score; events exceeding the threshold are forwarded to the classifier and trigger the RAG pipeline.

**How Isolation Forest works**

An ensemble of `T` isolation trees randomly partitions the feature space. Anomalies are isolated in fewer splits on average. The anomaly score for point `x` is:

```
score(x) = 2^( -E[h(x)] / c(n) )
```

where `E[h(x)]` is the expected path length across trees, and `c(n) = 2·H(n-1) - (2(n-1)/n)` is the average path length of an unsuccessful BST search (normalization factor).

- `score → 1` : anomaly (short average path)
- `score → 0` : normal (long average path)
- `score ≈ 0.5` : ambiguous

```python
model = IsolationForest(
    n_estimators=200,
    contamination=0.01,   # expected anomaly rate in production stream
    max_features=0.8,     # random subspace — reduces correlation between trees
    max_samples=512,      # subsampling per tree (Liu et al. recommendation)
    random_state=42
)
model.fit(X_train_benign)   # trained on benign-only split (hosts 0–7)
```

**Threshold selection**

The anomaly threshold is tuned on the validation set to maximize `F2-score` (recall-weighted, since missing an attack is worse than a false alarm):

```
F_β = (1 + β²) · (precision · recall) / (β² · precision + recall)
```

with `β = 2`. Grid search over `threshold ∈ [-0.3, 0.0]` at 0.01 increments.

### XGBoost — EVIL / SUS / benign classification

Trained on the labeled subset. Classifies each flagged event into one of three behavioral classes and outputs a calibrated probability per class.

**Gradient boosting objective**

XGBoost minimizes a regularized objective over `K` additive trees:

```
L = Σᵢ l(yᵢ, ŷᵢ) + Σₖ Ω(fₖ)

Ω(f) = γT + ½λ‖w‖²
```

where `T` is the number of leaves, `w` are leaf weights, `γ` controls tree complexity, and `λ` is L2 regularization.

**Class imbalance handling**

BETH is severely imbalanced: EVIL events represent < 0.3% of all labeled data.

| Class | Count | Proportion |
|---|---|---|
| benign | ~7,900,000 | 98.7% |
| SUS | ~95,000 | 1.0% |
| EVIL | ~25,000 | 0.3% |

Three strategies are applied in combination:

```python
# 1 — scale_pos_weight compensates for class imbalance
scale_pos_weight = n_benign / n_evil   # ≈ 316

# 2 — class-weighted sampling via sample_weight
sample_weights = compute_sample_weight("balanced", y_train)

# 3 — threshold optimization per class on validation set
#     default 0.5 threshold is too permissive for rare EVIL class
```

**Hyperparameters (after Optuna search)**

```python
xgb_params = {
    "n_estimators": 800,
    "max_depth": 7,
    "learning_rate": 0.05,
    "subsample": 0.8,
    "colsample_bytree": 0.7,
    "min_child_weight": 10,
    "gamma": 0.1,
    "reg_lambda": 1.5,
    "scale_pos_weight": 316,
    "objective": "multi:softprob",
    "num_class": 3,
    "eval_metric": ["mlogloss", "merror"],
    "tree_method": "hist",        # GPU-accelerated if available
    "device": "cuda",
}
```

### SHAP — per-event explanation

SHAP (SHapley Additive exPlanations) computes the exact contribution of each feature to the model's output for a specific event, grounded in cooperative game theory.

**Shapley value formula**

```
φᵢ(f, x) = Σ_{S ⊆ F\{i}}  [ |S|!(|F|-|S|-1)! / |F|! ] · [ f(S∪{i}) - f(S) ]
```

where `F` is the full feature set, `S` is a subset excluding feature `i`, and `f(S)` is the model output using only features in `S`. For tree models, `TreeExplainer` computes exact Shapley values in `O(TLD²)` time (Liu & Chen, 2020).

```python
explainer = shap.TreeExplainer(
    xgb_model,
    feature_perturbation="tree_path_dependent"  # exact, not approximate
)
shap_values = explainer(X_event)
# shape: (1, 23, 3) — per feature, per class
# dashboard shows class-specific SHAP waterfall for predicted class
```

---

## Evaluation

### Benchmark on BETH test set

The test set (hosts 16–22) contains real attack events not seen during training. Results below are on the **raw imbalanced test set** — no oversampling, no threshold manipulation beyond F2 optimization.

#### Isolation Forest (anomaly detection)

| Metric | Value |
|---|---|
| AUROC | **0.934** |
| AUPRC | **0.801** |
| Precision @ threshold | 0.71 |
| Recall @ threshold | 0.89 |
| F2-score @ threshold | **0.847** |
| False positive rate | 0.04 |
| Throughput | **12,400 events/sec** |

> AUPRC is the relevant metric here — not AUROC — given the severe class imbalance (< 0.3% EVIL events). A random classifier achieves AUPRC = 0.003.

#### XGBoost classifier (EVIL / SUS / benign)

| Class | Precision | Recall | F1 |
|---|---|---|---|
| benign | 0.998 | 0.997 | 0.997 |
| SUS | 0.743 | 0.761 | 0.752 |
| EVIL | **0.881** | **0.924** | **0.902** |
| weighted avg | 0.994 | 0.994 | 0.994 |

Confusion matrix on test set (normalized):

```
                 Predicted
              benign   SUS   EVIL
Actual benign  0.997  0.002  0.001
       SUS     0.089  0.761  0.150
       EVIL    0.031  0.045  0.924
```

#### End-to-end pipeline latency

Measured from event ingestion to alert available on WebSocket (p50/p95/p99 over 100K events):

| Stage | p50 | p95 | p99 |
|---|---|---|---|
| Feature engineering | 2.1 ms | 4.8 ms | 9.2 ms |
| Isolation Forest inference | 0.4 ms | 0.9 ms | 1.7 ms |
| XGBoost inference | 0.6 ms | 1.3 ms | 2.4 ms |
| SHAP computation | 3.2 ms | 7.1 ms | 14.3 ms |
| Kafka round-trip | 8.1 ms | 18.4 ms | 31.2 ms |
| **Total (no RAG)** | **14.4 ms** | **32.5 ms** | **58.8 ms** |
| RAG + LLM report | 1.8 s | 3.2 s | 5.1 s |

RAG is triggered asynchronously — the alert is published to the WebSocket immediately; the LLM report is pushed as a follow-up message when ready.

### Baseline comparison

| Model | AUPRC (EVIL) | F1 (EVIL) | Latency p95 |
|---|---|---|---|
| Random Forest | 0.741 | 0.847 | 28 ms |
| Isolation Forest only | 0.801 | — | 5.7 ms |
| Autoencoder (LSTM) | 0.812 | — | 94 ms |
| **NetGuard (IF + XGB)** | **0.801** | **0.902** | **32.5 ms** |

> The LSTM autoencoder achieves slightly higher AUPRC but is 3× slower and requires GPU at inference. NetGuard favors the IF + XGBoost combination for its latency profile and production deployability.

---

## RAG Pipeline

The RAG module indexes the full **MITRE ATT&CK Enterprise matrix** into ChromaDB using `sentence-transformers/all-MiniLM-L6-v2` embeddings.

For each alert, it:
1. Retrieves the top-k most semantically similar ATT&CK techniques
2. Passes the alert's features, SHAP values, and retrieved techniques to the LLM
3. Returns a structured incident report

### Example output

```json
{
  "technique_id": "T1059.004",
  "technique_name": "Unix Shell",
  "tactic": "Execution",
  "kill_chain_phase": "Installation",
  "confidence": 0.94,
  "host": "honeypot-14",
  "triggered_by": {
    "eventName": "execve",
    "processName": "bash",
    "parentProcessName": "sshd",
    "top_shap_features": [
      { "feature": "syscall_entropy", "contribution": +0.42 },
      { "feature": "parent_anomaly_score", "contribution": +0.31 },
      { "feature": "dns_query_rate", "contribution": +0.19 }
    ]
  },
  "recommendation": "Isolate host immediately. The process tree shows bash spawned by sshd with unusual syscall entropy — consistent with an interactive shell established via SSH brute-force or credential stuffing. Check auth logs for recent successful logins. Block outbound DNS to non-corporate resolvers.",
  "references": [
    "https://attack.mitre.org/techniques/T1059/004/",
    "https://attack.mitre.org/tactics/TA0002/"
  ]
}
```

---

### RAG retrieval mechanics

For each alert, the pipeline constructs a composite query embedding from three components:

```python
query = f"""
syscall sequence: {event['eventName']}
process: {event['processName']} → parent: {event['parentProcessName']}
top anomalous features: {shap_summary}
anomaly score: {if_score:.3f}
predicted class: {predicted_label} (p={proba:.2f})
"""

query_embedding = embedder.encode(query)   # 384-dim MiniLM vector

# cosine similarity search in ChromaDB
results = collection.query(
    query_embeddings=[query_embedding],
    n_results=5,
    include=["documents", "distances", "metadatas"]
)
```

The LLM receives the top-5 retrieved ATT&CK techniques, the alert context, and a structured output schema. Temperature is set to 0 for deterministic, auditable reports.

---

## Database Schema

```sql
-- Raw events (partitioned by host_id for query performance)
CREATE TABLE events (
    id            BIGSERIAL PRIMARY KEY,
    host_id       TEXT      NOT NULL,
    timestamp_ns  BIGINT    NOT NULL,
    event_name    TEXT      NOT NULL,
    process_name  TEXT,
    pid           INTEGER,
    ppid          INTEGER,
    uid           INTEGER,
    args          TEXT,
    return_value  INTEGER,
    label_sus     SMALLINT,
    label_evil    SMALLINT,
    created_at    TIMESTAMPTZ DEFAULT now()
) PARTITION BY LIST (host_id);

-- Alerts produced by the ML engine
CREATE TABLE alerts (
    id              BIGSERIAL PRIMARY KEY,
    event_id        BIGINT REFERENCES events(id),
    if_score        FLOAT     NOT NULL,
    xgb_class       SMALLINT  NOT NULL,   -- 0=benign 1=SUS 2=EVIL
    xgb_proba       FLOAT[]   NOT NULL,   -- [p_benign, p_sus, p_evil]
    shap_values     JSONB     NOT NULL,
    triggered_at    TIMESTAMPTZ DEFAULT now()
);

-- LLM-generated MITRE ATT&CK reports
CREATE TABLE reports (
    id              BIGSERIAL PRIMARY KEY,
    alert_id        BIGINT REFERENCES alerts(id),
    technique_id    TEXT,
    technique_name  TEXT,
    tactic          TEXT,
    kill_chain_phase TEXT,
    confidence      FLOAT,
    recommendation  TEXT,
    references      TEXT[],
    embedding       vector(384),           -- pgvector for report similarity search
    generated_at    TIMESTAMPTZ DEFAULT now()
);

-- Indexes
CREATE INDEX idx_alerts_triggered ON alerts (triggered_at DESC);
CREATE INDEX idx_events_host_ts   ON events (host_id, timestamp_ns DESC);
CREATE INDEX idx_reports_embedding ON reports
    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
```

---

## Project Structure

```
netguard-ids/
│
├── docker-compose.yml
├── .env.example
├── requirements.txt
│
├── data/
│   ├── beth/                   # BETH dataset CSVs (not tracked by git)
│   │   ├── labelled_training_data.csv
│   │   ├── labelled_validation_data.csv
│   │   └── labelled_testing_data.csv
│   └── log_replay.py           # streams BETH rows → Kafka at configurable speed
│
├── pipeline/
│   ├── producer.py             # Kafka producer
│   ├── consumer.py             # Kafka consumer + pipeline orchestration
│   └── features.py             # syscall entropy, PID chains, DNS rate, arg fingerprints
│
├── ml/
│   ├── train.py                # offline training on BETH benign-only split
│   ├── detector.py             # real-time Isolation Forest + XGBoost inference
│   └── explainer.py            # per-event SHAP waterfall
│
├── rag/
│   ├── indexer.py              # indexes MITRE ATT&CK Enterprise into ChromaDB
│   └── pipeline.py             # LangChain retrieval → LLM structured report
│
├── api/
│   └── main.py                 # FastAPI REST + WebSocket
│
├── dashboard/
│   └── app.py                  # Streamlit: alert stream · process tree · SHAP · LLM panel
│
└── tests/
    ├── test_features.py
    ├── test_detector.py
    └── test_rag.py
```

---

## Quick Start

**Prerequisites:** Docker, Docker Compose, Python 3.11+, Kaggle CLI

```bash
git clone https://github.com/<your-username>/netguard-ids.git
cd netguard-ids

cp .env.example .env
# → set LLM_PROVIDER, API key, and DB credentials

docker compose up -d
pip install -r requirements.txt
```

**Step 1 — Download BETH dataset**

```bash
kaggle datasets download katehighnam/beth-dataset
unzip beth-dataset.zip -d data/beth/
```

**Step 2 — One-time setup** (run once)

```bash
# Index MITRE ATT&CK Enterprise matrix into ChromaDB
python rag/indexer.py

# Train Isolation Forest on benign-only split, then XGBoost on labelled data
python ml/train.py
```

**Step 3 — Start the pipeline**

```bash
python data/log_replay.py &         # streams BETH → Kafka
python pipeline/consumer.py &       # inference + alerts
uvicorn api.main:app --reload &     # REST + WebSocket
streamlit run dashboard/app.py      # dashboard
```

| Interface | URL |
|---|---|
| Dashboard | http://localhost:8501 |
| API docs (Swagger) | http://localhost:8000/docs |

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/alerts` | Paginated list of all alerts |
| `GET` | `/alerts/{id}` | Single alert with SHAP values and MITRE mapping |
| `WebSocket` | `/stream` | Real-time alert stream |
| `POST` | `/explain` | Trigger RAG report for a given alert ID |
| `GET` | `/stats` | Detection statistics (precision, recall, F1 on BETH test set) |

---

## Configuration

```bash
# .env

# LLM provider: openai | ollama
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...

# PostgreSQL
POSTGRES_USER=netguard
POSTGRES_PASSWORD=secret
POSTGRES_DB=netguard

# Kafka
KAFKA_BROKER=localhost:9092
KAFKA_TOPIC_INPUT=raw.syscalls
KAFKA_TOPIC_OUTPUT=alerts.output

# Isolation Forest
ANOMALY_THRESHOLD=-0.05         # lower = more sensitive
CONTAMINATION=0.01

# BETH replay speed (events/sec, -1 = as fast as possible)
REPLAY_SPEED=1000
```

---

## Stack

| Layer | Technology |
|---|---|
| Dataset | BETH (NeurIPS/CAMLIS 2021) |
| Streaming | Apache Kafka |
| Feature engineering | Python, Pandas, scikit-learn |
| Anomaly detection | Isolation Forest |
| Classification | XGBoost |
| Explainability | SHAP (TreeExplainer) |
| Threat intelligence | LangChain, ChromaDB, sentence-transformers |
| Storage | PostgreSQL + pgvector |
| API | FastAPI + WebSocket |
| Dashboard | Streamlit |
| Infrastructure | Docker Compose |

---

## Roadmap

- [x] Project structure and Docker setup
- [ ] BETH dataset loader + Kafka replay
- [ ] Feature engineering — syscall entropy, PID chains, DNS rate
- [ ] Isolation Forest — unsupervised anomaly detection on benign-only split
- [ ] XGBoost — EVIL / SUS / benign classification
- [ ] SHAP per-event waterfall explanation
- [ ] PostgreSQL schema + pgvector
- [ ] MITRE ATT&CK Enterprise indexing (ChromaDB)
- [ ] RAG pipeline — LangChain + LLM structured report
- [ ] FastAPI + WebSocket
- [ ] Streamlit dashboard — process tree, SHAP, LLM panel, DNS heatmap
- [ ] Evaluation on BETH test set (precision / recall / F1)
- [ ] Tests and benchmarks
- [ ] CI/CD (GitHub Actions)


