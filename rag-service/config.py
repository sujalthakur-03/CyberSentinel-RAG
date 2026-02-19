"""
Centralized configuration for the CyberSentinel RAG service.
All tunables live here — override via environment variables in production.
"""

import os


# ---------------------------------------------------------------------------
# OpenSearch
# ---------------------------------------------------------------------------
OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "cybersentinel-database")
OPENSEARCH_PORT = int(os.getenv("OPENSEARCH_PORT", "9200"))
OPENSEARCH_SCHEME = os.getenv("OPENSEARCH_SCHEME", "http")

# Index patterns
LOG_INDEX_PATTERN = os.getenv("LOG_INDEX_PATTERN", "logs-*")
UBA_INDEX = os.getenv("UBA_INDEX", "uba-behavior-summary")
INSIGHTS_INDEX = os.getenv("INSIGHTS_INDEX", "uba-insights")

# ---------------------------------------------------------------------------
# Embedding model (sentence-transformers)
# ---------------------------------------------------------------------------
EMBEDDING_MODEL_NAME = os.getenv(
    "EMBEDDING_MODEL_NAME", "all-MiniLM-L6-v2"
)
VECTOR_DIMENSION = int(os.getenv("VECTOR_DIMENSION", "384"))

# ---------------------------------------------------------------------------
# Ollama LLM
# ---------------------------------------------------------------------------
OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL", "http://164.52.194.98:11434"
)
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "vicuna:13b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

# ---------------------------------------------------------------------------
# Query rewriting (T5 grammar correction)
# ---------------------------------------------------------------------------
QUERY_REWRITE_ENABLED = os.getenv("QUERY_REWRITE_ENABLED", "true").lower() == "true"
QUERY_REWRITE_MODEL = os.getenv(
    "QUERY_REWRITE_MODEL", "vennify/t5-base-grammar-correction"
)

# ---------------------------------------------------------------------------
# Retrieval tuning
# ---------------------------------------------------------------------------
TOP_K_LOGS = int(os.getenv("TOP_K_LOGS", "25"))
TOP_K_VECTORS = int(os.getenv("TOP_K_VECTORS", "3"))
MAX_CONTEXT_CHARS = int(os.getenv("MAX_CONTEXT_CHARS", "3500"))
MAX_AGGREGATED_BLOCKS = int(os.getenv("MAX_AGGREGATED_BLOCKS", "8"))

# Hard ceiling on log documents returned per single keyword query.
# Busy IPs (scanners, C2 beacons, DNS resolvers) can match tens of thousands
# of entries.  Without a cap, aggregation burns CPU and the resulting context
# is too noisy for useful LLM reasoning.
#
# Why statistical sampling is sufficient for SOC analysis:
#   - SOC triage needs *pattern identification*, not exhaustive evidence.
#   - 500 most-recent events already capture the activity profile (event-type
#     distribution, affected hosts, user accounts, time boundaries).
#   - Full forensic evidence collection is a downstream DFIR workflow that
#     queries OpenSearch directly — the RAG service is an analyst aid, not
#     a forensic export tool.
MAX_LOG_HITS_PER_QUERY = int(os.getenv("MAX_LOG_HITS_PER_QUERY", "500"))

# ---------------------------------------------------------------------------
# Time-range safety
# ---------------------------------------------------------------------------
# Default lookback window for keyword searches on logs-* indices.
# Queries without an explicit time expression are bounded to this window
# to prevent full-index scans in high-volume SIEM environments.
DEFAULT_LOG_TIME_RANGE_HOURS = int(os.getenv("DEFAULT_LOG_TIME_RANGE_HOURS", "24"))

# Maximum age of UBA behavioral summaries considered during vector search.
# Older summaries are filtered out *before* kNN scoring so stale profiles
# do not dominate retrieval results.
VECTOR_LOOKBACK_DAYS = int(os.getenv("VECTOR_LOOKBACK_DAYS", "30"))

# ---------------------------------------------------------------------------
# Session context (follow-up questions)
# ---------------------------------------------------------------------------
# How long a session's last-retrieval context is kept in memory.
# After this TTL, the session is evicted and follow-up queries start fresh.
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "10"))

# Number of consecutive entity-less follow-up queries before inherited
# entities are forcibly cleared.  Prevents "drift" where an analyst pivots
# to a new topic but old IPs/hosts keep being searched silently.
FOLLOWUP_ENTITY_RESET_THRESHOLD = int(os.getenv("FOLLOWUP_ENTITY_RESET_THRESHOLD", "3"))

# ---------------------------------------------------------------------------
# Insight deduplication
# ---------------------------------------------------------------------------
# Cosine similarity threshold for semantic deduplication of stored insights.
# Even when the context_hash differs (e.g. slightly different log windows),
# two insights may be semantically near-identical.  In SOC RAG systems this
# is common because analysts rephrase the same question or the same alert
# fires across adjacent time windows.  Storing near-duplicates inflates the
# insights index and degrades future vector retrieval quality — the kNN
# top-K slots get consumed by paraphrases of the same explanation instead
# of diverse, complementary insights.
INSIGHT_SIMILARITY_THRESHOLD = float(os.getenv("INSIGHT_SIMILARITY_THRESHOLD", "0.92"))

# ---------------------------------------------------------------------------
# Risk score calibration
# ---------------------------------------------------------------------------
# Percentile rank above which a UBA risk score is classified as "high-risk"
# for context ordering purposes.  0.80 means the top 20 % of retrieved
# scores are placed in the high-risk section of the LLM context.
#
# Why relative ranking matters in SOC environments:
#   Absolute thresholds (e.g. "risk >= 70") assume a stable scoring model.
#   In practice, alert volumes shift as detection rules evolve, new data
#   sources are on-boarded, and tenant behavior changes seasonally.  A score
#   of 65 that was "medium" last month may be the highest value this month
#   after a rule recalibration.  Percentile ranking adapts automatically to
#   the *current* distribution of retrieved results, ensuring the LLM always
#   sees the most anomalous signals first regardless of absolute calibration.
RISK_PERCENTILE_THRESHOLD = float(os.getenv("RISK_PERCENTILE_THRESHOLD", "0.80"))

# Minimum number of UBA results required to use percentile ranking.
# Below this count the distribution is too sparse for meaningful percentiles,
# so we fall back to the absolute _HIGH_RISK_THRESHOLD (70.0).
RISK_PERCENTILE_MIN_SAMPLES = int(os.getenv("RISK_PERCENTILE_MIN_SAMPLES", "3"))
