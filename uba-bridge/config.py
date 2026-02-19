"""
UBA Bridge configuration — all tunables via environment variables.
"""

import os

# ---------------------------------------------------------------------------
# OpenSearch
# ---------------------------------------------------------------------------
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "cybersentinel-database")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_URL = f"http://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"

# ---------------------------------------------------------------------------
# RAG Service
# ---------------------------------------------------------------------------
RAG_SERVICE_URL = os.getenv("RAG_SERVICE_URL", "http://cybersentinel-rag:8000")

# ---------------------------------------------------------------------------
# Polling
# ---------------------------------------------------------------------------
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "300"))

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
SETUP_ON_STARTUP = os.getenv("SETUP_ON_STARTUP", "true").lower() == "true"

# ---------------------------------------------------------------------------
# Bridge service
# ---------------------------------------------------------------------------
BRIDGE_HOST = os.getenv("BRIDGE_HOST", "0.0.0.0")
BRIDGE_PORT = int(os.getenv("BRIDGE_PORT", "8001"))

# Webhook URL that alerting monitors will POST to.
# Inside Docker network: http://cybersentinel-uba-bridge:8001
WEBHOOK_URL = os.getenv(
    "WEBHOOK_URL", "http://cybersentinel-uba-bridge:8001/webhook/alert"
)

# ---------------------------------------------------------------------------
# Indices
# ---------------------------------------------------------------------------
LOG_INDEX = "logs-*"
ANOMALY_RESULTS_INDEX = ".opendistro-anomaly-results-*"

# ---------------------------------------------------------------------------
# Enrichment
# ---------------------------------------------------------------------------
ENRICHMENT_LOOKBACK_MINUTES = int(os.getenv("ENRICHMENT_LOOKBACK_MINUTES", "30"))
ENRICHMENT_TOP_N = int(os.getenv("ENRICHMENT_TOP_N", "5"))

# ---------------------------------------------------------------------------
# Polling batch size
# ---------------------------------------------------------------------------
POLL_BATCH_SIZE = int(os.getenv("POLL_BATCH_SIZE", "500"))

# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
DEDUP_TTL_SECONDS = int(os.getenv("DEDUP_TTL_SECONDS", "3600"))
