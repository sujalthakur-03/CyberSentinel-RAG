# CyberSentinel RAG

An AI-powered cybersecurity analyst assistant that combines **Retrieval-Augmented Generation (RAG)** with **User Behavior Analytics (UBA)** to help SOC analysts investigate threats, analyze anomalies, and query security logs using natural language.

## Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────────┐
│  Wazuh/SIEM  │───►│    Kafka      │───►│   OpenSearch      │
│  Agents      │    │  (lz4 comp.) │    │  (AD Plugin)      │
└──────────────┘    └──────────────┘    └────────┬─────────┘
                                                 │
                              ┌───────────────────┤
                              │                   │
                    ┌─────────▼────────┐  ┌───────▼──────────┐
                    │   UBA Bridge     │  │  RAG Service      │
                    │  - Anomaly Poll  │  │  - Query Rewrite  │
                    │  - Enrichment    │  │  - Entity Detect  │
                    │  - Summary Build │  │  - Hybrid Search  │
                    │  - Alert Handle  │  │  - LLM Answer     │
                    └─────────┬────────┘  └───────▲──────────┘
                              │                   │
                              └───────────────────┘
                              (POST /index/uba)
```

### Pipeline Flow

1. **Log Ingestion**: Wazuh agents collect endpoint security logs and ship them through Kafka into OpenSearch `logs-*` indices.
2. **Anomaly Detection**: OpenSearch's built-in Anomaly Detection plugin runs 5 ML detectors (Random Cut Forest) that continuously analyze log patterns.
3. **Alert Monitoring**: 4 OpenSearch alerting monitors watch for threshold breaches and trigger webhook notifications to the UBA Bridge.
4. **UBA Bridge Processing**: Polls anomaly results every 5 minutes, enriches them with log context, builds human-readable behavioral summaries, and indexes them into `uba-behavior-summary`.
5. **RAG Query**: Analysts ask natural language questions. The RAG service rewrites misspelled queries, classifies intent, runs hybrid search (keyword + vector), assembles context, and sends it to Vicuna-13B for a grounded answer.

## Services

| Service | Port | Description |
|---------|------|-------------|
| `cybersentinel-database` | 9200 | OpenSearch with Anomaly Detection plugin |
| `cybersentinel-database-dashboard` | 5601 | OpenSearch Dashboards |
| `cybersentinel-endpoint-processor` | 9092 | Kafka message broker |
| `cybersentinel-queue-coordinator` | 2181 | Zookeeper |
| `cybersentinel-secret-vault` | 8200 | HashiCorp Vault |
| `cybersentinel-rag` | 8000 | RAG query service |
| `cybersentinel-uba-bridge` | 8002 | UBA anomaly-to-RAG pipeline |

## RAG Service

The core query engine at `rag-service/`.

### Components

- **`main.py`** — FastAPI application with `/query`, `/health`, and `/index/uba` endpoints. Accepts analyst questions and returns LLM-generated answers grounded in retrieved log and UBA data.

- **`query_rewriter.py`** — Fixes spelling and grammar in user queries using a T5-base grammar correction model (`vennify/t5-base-grammar-correction`). Runs in ~100-300ms on CPU. Falls back to original query on any error.

- **`entity_detector.py`** — Extracts structured entities from natural language queries:
  - IPv4 addresses (RFC-1918 and public)
  - Hostnames (FQDNs, internal hyphenated names, underscore-separated system IDs, ALL-CAPS identifiers)
  - Usernames (`user:value` patterns)
  - Time ranges ("last 7 days", "past 24 hours", "yesterday", etc.)
  - Behavioral keywords (anomaly, lateral movement, exfiltration, etc.)
  - **Query intent classification** into 4 categories: `aggregate`, `behavioral`, `entity_investigation`, `general`

- **`retriever.py`** — Main retrieval orchestrator implementing intent-aware hybrid search:
  - **Keyword search** on `logs-*` with time-bounded queries and entity filters
  - **kNN vector search** on `uba-behavior-summary` using sentence-transformer embeddings (conditionally skipped for aggregate queries)
  - **Log aggregation** — groups raw logs by source IP, agent, or destination and produces structured blocks
  - **Dynamic context budget** — allocates block slots to log data vs UBA summaries based on query intent
  - **Context deduplication** — suppresses redundant UBA blocks for aggregate queries; annotates logs with UBA risk scores for other intents
  - **Session context** for follow-up questions with drift detection

- **`opensearch_client.py`** — OpenSearch client handling kNN vector search, keyword search with field boosting, and insight persistence with two-layer deduplication (hash-based + semantic similarity). Connection pool sized at 50 to support concurrent multi-worker searches.

- **`embedding.py`** — Sentence-transformers `all-MiniLM-L6-v2` model for generating 384-dimensional embeddings.

- **`llm_client.py`** — HTTP client for Ollama-hosted Vicuna-13B with a strict cybersecurity system prompt that enforces grounded answers. Uses a persistent httpx client with connection pooling (20 max connections, 10 keepalive) for efficient LLM communication.

- **`session_manager.py`** — In-memory session context with configurable TTL, entity inheritance for follow-up questions, and automatic drift reset.

- **`config.py`** — Centralized configuration with environment variable overrides for all tunable parameters.

### Query Intent System

The RAG service classifies every query into one of 4 intent categories, which controls retrieval strategy:

| Intent | Example Query | Vector Search | Log Size | UBA Budget |
|--------|--------------|---------------|----------|------------|
| `aggregate` | "Which agent has the most login failures?" | Skipped | 100 hits | 1 block |
| `behavioral` | "Show anomalous behavior for users" | Enabled | 25 hits | 6 blocks |
| `entity_investigation` | "What activity is from IP 10.0.0.5?" | Enabled | 25 hits | 3 blocks |
| `general` | "What happened today?" | Enabled | 25 hits | 3 blocks |

### Context Budget Allocation

| Intent | Log Blocks | High UBA | Low UBA |
|--------|-----------|----------|---------|
| `aggregate` | 7 | 1 | 0 |
| `behavioral` | 2 | 4 | 2 |
| `entity_investigation` | 4 | 2 | 1 |
| `general` | 4 | 2 | 1 |

## UBA Bridge

The anomaly detection to RAG pipeline at `uba-bridge/`.

### Components

- **`main.py`** — FastAPI application with `/webhook/alert` and `/health` endpoints. Runs background anomaly polling loop and optional auto-setup on startup.

- **`anomaly_poller.py`** — Polls OpenSearch anomaly results every 5 minutes (configurable). Filters by anomaly grade >= 0.5, batch-enriches entities, builds behavioral summaries, and posts them to the RAG service. Uses watermark tracking to avoid reprocessing.

- **`enrichment.py`** — Enriches anomaly entities with surrounding log context. Includes `enrich_entities_batch()` for efficient batch processing — 1 aggregation query per entity type instead of N individual queries.

- **`summary_builder.py`** — Generates human-readable behavioral summaries from enriched anomaly data using templates. Includes MITRE ATT&CK technique mapping (T1110, T1078, T1059, etc.) and risk score calculation.

- **`alert_handler.py`** — Processes webhook alerts from OpenSearch alerting monitors. Extracts trigger context, enriches with log data, and posts summaries to RAG.

- **`setup_detectors.py`** — Configures 5 anomaly detectors on OpenSearch:
  - `auth-failure-spike` — Authentication failure volume anomalies (30-min interval)
  - `port-scan-detector` — Network scanning behavior
  - `unusual-process-exec` — Abnormal process execution patterns
  - `data-exfiltration-volume` — Unusual outbound data volume
  - `off-hours-access` — Access during non-business hours

  Supports update-if-changed: stops, updates, and restarts detectors when configuration differs from running state.

- **`setup_monitors.py`** — Configures 4 alerting monitors:
  - `brute-force-threshold` — High auth failure count per source IP
  - `vpn-failure-spike` — VPN authentication failure spikes
  - `executable-drop` — Suspicious executable file creation
  - `mitre-technique-chain` — Multiple MITRE ATT&CK techniques from same source

- **`setup_ilm.py`** — Index State Management policies:
  - `logs-lifecycle` — Auto-delete `logs-*` indices older than 90 days
  - `anomaly-results-lifecycle` — Auto-delete `.opendistro-anomaly-results-*` older than 7 days
  - Includes `cleanup_empty_indices()` for removing tombstone indices with 0 documents

- **`setup_all.py`** — Orchestrates full setup: detectors, monitors, and ILM policies.

- **`config.py`** — UBA Bridge configuration with environment variable overrides.

## Deployment

### Prerequisites

- Docker and Docker Compose
- Ollama server with `vicuna:13b` model loaded (configured via `OLLAMA_BASE_URL`)
- At least 16 GB RAM recommended for all services

### Quick Start

```bash
# Clone the repository
git clone https://github.com/sujalthakur-03/CyberSentinel-RAG.git
cd CyberSentinel-RAG

# Start all services
docker compose up -d

# Verify services are healthy
docker compose ps

# Test the RAG endpoint
curl -s -X POST 'http://localhost:8000/query' \
  -H 'Content-Type: application/json' \
  -d '{"question": "Show me recent security events"}' | python3 -m json.tool
```

### Environment Variables

#### RAG Service

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `cybersentinel-database` | OpenSearch hostname |
| `OPENSEARCH_PORT` | `9200` | OpenSearch port |
| `OLLAMA_BASE_URL` | `http://164.52.194.98:11434` | Ollama LLM server URL |
| `OLLAMA_MODEL` | `vicuna:13b` | LLM model name |
| `EMBEDDING_MODEL_NAME` | `all-MiniLM-L6-v2` | Sentence-transformer model |
| `TOP_K_LOGS` | `25` | Number of log hits per keyword search |
| `TOP_K_VECTORS` | `3` | Number of UBA vector search results |
| `MAX_CONTEXT_CHARS` | `3500` | Maximum context window for LLM |
| `MAX_AGGREGATED_BLOCKS` | `8` | Maximum grouped log blocks |
| `QUERY_REWRITE_ENABLED` | `true` | Enable T5 query spell correction |
| `DEFAULT_LOG_TIME_RANGE_HOURS` | `24` | Default lookback window |
| `SESSION_TTL_MINUTES` | `10` | Session context TTL |

#### UBA Bridge

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENSEARCH_HOST` | `cybersentinel-database` | OpenSearch hostname |
| `OPENSEARCH_PORT` | `9200` | OpenSearch port |
| `RAG_SERVICE_URL` | `http://cybersentinel-rag:8000` | RAG service URL |
| `POLL_INTERVAL_SECONDS` | `300` | Anomaly polling interval |
| `POLL_BATCH_SIZE` | `500` | Max anomalies per poll cycle |
| `SETUP_ON_STARTUP` | `true` | Auto-setup detectors/monitors on start |
| `ENRICHMENT_LOOKBACK_MINUTES` | `30` | Log context window for enrichment |

## API Endpoints

### RAG Service (port 8000)

#### `POST /query`
Ask a natural language question about security logs.

```json
{
  "question": "Which agent has the most login failures in the last 7 days?",
  "session_id": "optional-session-id"
}
```

Response:
```json
{
  "answer": "Based on the retrieved log data...",
  "sources_used": 25,
  "session_id": "abc123",
  "debug": {
    "rewritten_query": "Which agent has the most login failures in the last 7 days?",
    "entities": { "ips": [], "hostnames": [], "query_intent": "aggregate" },
    "time_range_hours": 168
  }
}
```

#### `GET /health`
Health check endpoint.

#### `POST /index/uba`
Index a UBA behavioral summary (used internally by UBA Bridge).

### UBA Bridge (port 8002)

#### `POST /webhook/alert`
Receives alert webhooks from OpenSearch alerting monitors.

#### `GET /health`
Health check endpoint.

## Infrastructure Optimizations

### Concurrency & Performance
- **Multi-worker Uvicorn (4 workers)** — RAG service runs 4 separate Python processes, eliminating GIL contention for T5 query rewriting and embedding inference under concurrent load
- **httpx connection pooling** — Persistent HTTP client with 20 max connections and 10 keepalive connections for Ollama LLM calls, eliminating per-request TCP handshake overhead
- **OpenSearch connection pool (50)** — Sized to support 4 workers × 4 parallel searches per query without connection starvation
- **RAG container resources** — 4 CPU cores / 4 GB RAM to support multi-worker model loading

### Storage & Efficiency
- **Kafka lz4 compression** — 40-60% storage savings on log transport with negligible CPU overhead
- **OpenSearch 2 GB heap** — Reduced GC pressure, leaves headroom for OS page cache
- **Index Lifecycle Management** — Automatic cleanup of old logs (90 days) and anomaly results (7 days)
- **Batch enrichment** — Single aggregation query per entity type instead of N individual queries per poll cycle
- **Anomaly grade filtering** — Only anomalies with grade >= 0.5 are processed (filters noise)
- **auth-failure-spike interval** — 30-minute detection interval to reduce result volume

## Tech Stack

- **LLM**: Vicuna-13B via Ollama
- **Embeddings**: all-MiniLM-L6-v2 (sentence-transformers, 384 dimensions)
- **Query Correction**: T5-base grammar correction (vennify/t5-base-grammar-correction)
- **Search Engine**: OpenSearch with Anomaly Detection and Alerting plugins
- **Message Queue**: Apache Kafka with Zookeeper
- **Secrets**: HashiCorp Vault
- **Framework**: FastAPI + Uvicorn (4 workers)
- **Containerization**: Docker Compose

## Project Structure

```
CyberSentinel-RAG/
├── docker-compose.yml          # All service definitions
├── rag-service/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── main.py                 # FastAPI app
│   ├── config.py               # Configuration
│   ├── query_rewriter.py       # T5 spell/grammar correction
│   ├── entity_detector.py      # Entity extraction + intent classification
│   ├── retriever.py            # Hybrid search orchestrator
│   ├── opensearch_client.py    # OpenSearch operations
│   ├── embedding.py            # Sentence-transformer embeddings
│   ├── llm_client.py           # Ollama/Vicuna client
│   └── session_manager.py      # Session context management
└── uba-bridge/
    ├── Dockerfile
    ├── requirements.txt
    ├── main.py                 # FastAPI app + polling loop
    ├── config.py               # Configuration
    ├── anomaly_poller.py       # Anomaly result polling + processing
    ├── enrichment.py           # Log context enrichment
    ├── summary_builder.py      # Behavioral summary generation
    ├── alert_handler.py        # Webhook alert processing
    ├── setup_detectors.py      # Anomaly detector configuration
    ├── setup_monitors.py       # Alert monitor configuration
    ├── setup_ilm.py            # Index lifecycle policies
    └── setup_all.py            # Full setup orchestrator
```
