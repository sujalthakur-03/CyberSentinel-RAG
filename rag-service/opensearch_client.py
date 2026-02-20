"""
OpenSearch client factory and index bootstrapping.

Provides:
 - get_client()           → singleton OpenSearch connection
 - ensure_uba_index()     → create uba-behavior-summary with knn mapping
 - keyword_search()       → multi-match across logs-* with mandatory time filter
 - vector_search()        → kNN similarity on uba-behavior-summary with time decay
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from opensearchpy import OpenSearch

import config

logger = logging.getLogger(__name__)

_client: OpenSearch | None = None


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def get_client() -> OpenSearch:
    """Return a reusable OpenSearch client (no auth — security plugin disabled)."""
    global _client
    if _client is None:
        _client = OpenSearch(
            hosts=[{
                "host": config.OPENSEARCH_HOST,
                "port": config.OPENSEARCH_PORT,
            }],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=30,
            pool_maxsize=50,
        )
        logger.info(
            "Connected to OpenSearch at %s:%s",
            config.OPENSEARCH_HOST,
            config.OPENSEARCH_PORT,
        )
    return _client


# ---------------------------------------------------------------------------
# Index bootstrapping
# ---------------------------------------------------------------------------

UBA_MAPPING = {
    "settings": {
        "index": {
            "knn": True,
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    },
    "mappings": {
        "properties": {
            "user_id": {"type": "keyword"},
            "hostname": {"type": "keyword"},
            "summary": {"type": "text"},
            "risk_score": {"type": "float"},
            "tags": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "embedding": {
                "type": "knn_vector",
                "dimension": config.VECTOR_DIMENSION,
                "method": {
                    "name": "hnsw",
                    "space_type": "cosinesimil",
                    "engine": "lucene",
                    "parameters": {
                        "ef_construction": 256,
                        "m": 48,
                    },
                },
            },
        }
    },
}


# ---------------------------------------------------------------------------
# uba-insights index — stores useful LLM explanations for future retrieval
# ---------------------------------------------------------------------------
# This enables "RAG learning without training": when the LLM produces a
# high-quality explanation, it gets persisted as an insight document with
# its own embedding.  Future vector searches can surface past insights as
# a low-priority supplementary source.
#
# Deduplication: the context_hash field (SHA-256 of summarised context)
# prevents storing multiple insights for the same retrieved data.

INSIGHTS_MAPPING = {
    "settings": {
        "index": {
            "knn": True,
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    },
    "mappings": {
        "properties": {
            "question": {"type": "text"},
            "answer": {"type": "text"},
            "context_hash": {"type": "keyword"},
            "entities_ip": {"type": "keyword"},
            "entities_hostname": {"type": "keyword"},
            "entities_username": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "embedding": {
                "type": "knn_vector",
                "dimension": config.VECTOR_DIMENSION,
                "method": {
                    "name": "hnsw",
                    "space_type": "cosinesimil",
                    "engine": "lucene",
                    "parameters": {
                        "ef_construction": 256,
                        "m": 48,
                    },
                },
            },
        }
    },
}


def ensure_uba_index() -> None:
    """Create the UBA behaviour-summary index if it does not exist."""
    client = get_client()
    if not client.indices.exists(index=config.UBA_INDEX):
        client.indices.create(index=config.UBA_INDEX, body=UBA_MAPPING)
        logger.info("Created index: %s", config.UBA_INDEX)
    else:
        logger.info("Index already exists: %s", config.UBA_INDEX)


def ensure_insights_index() -> None:
    """Create the uba-insights index if it does not exist."""
    client = get_client()
    if not client.indices.exists(index=config.INSIGHTS_INDEX):
        client.indices.create(index=config.INSIGHTS_INDEX, body=INSIGHTS_MAPPING)
        logger.info("Created index: %s", config.INSIGHTS_INDEX)
    else:
        logger.info("Index already exists: %s", config.INSIGHTS_INDEX)


# ---------------------------------------------------------------------------
# Search helpers
# ---------------------------------------------------------------------------

def _time_range_filter(field: str, hours: Optional[int] = None, days: Optional[int] = None) -> dict:
    """
    Build an OpenSearch range clause for a timestamp field.
    Exactly one of *hours* or *days* must be provided.

    Used by both keyword and vector searches to enforce time-bounded queries —
    critical in high-volume SIEM environments where unbounded scans cause
    cluster pressure and return stale data.
    """
    if hours is not None:
        gte = datetime.now(timezone.utc) - timedelta(hours=hours)
    elif days is not None:
        gte = datetime.now(timezone.utc) - timedelta(days=days)
    else:
        raise ValueError("Provide hours or days")
    return {"range": {field: {"gte": gte.isoformat(), "lte": "now"}}}


def keyword_search(
    terms: list[str],
    index: str = config.LOG_INDEX_PATTERN,
    size: int = config.TOP_K_LOGS,
    lookback_hours: Optional[int] = None,
) -> list[dict]:
    """
    Multi-match keyword search across *index* (default logs-*).

    *terms*           — IPs, hostnames, or usernames extracted from the query.
    *lookback_hours*  — explicit time window; falls back to DEFAULT_LOG_TIME_RANGE_HOURS.

    SAFETY: every keyword query is bounded by a time filter.  An unbounded
    logs-* scan can return millions of docs and overwhelm both OpenSearch and
    the downstream context summariser.

    The *size* parameter is hard-capped to MAX_LOG_HITS_PER_QUERY regardless
    of what the caller requests.  This protects the aggregation layer from
    processing unbounded result sets when a busy IP matches thousands of logs.
    The most-recent N events (sorted desc) are statistically representative
    of activity patterns — SOC triage does not require exhaustive retrieval.
    """
    client = get_client()

    # Hard ceiling — never let a single query pull more than this
    effective_size = min(size, config.MAX_LOG_HITS_PER_QUERY)
    effective_hours = lookback_hours or config.DEFAULT_LOG_TIME_RANGE_HOURS

    # Comprehensive field list derived from the actual Wazuh/Fortigate/Windows
    # log schema.  Covers IPs, users, hosts, messages, rules, actions,
    # file integrity, Windows Sysmon, and raw logs — everything a SOC analyst
    # might ask about.  Bounded to ~30 fields to stay under OpenSearch's
    # 1024-clause limit even with multiple search terms.
    _SEARCH_FIELDS = [
        # Rule / alert metadata
        "rule.description", "rule.groups", "rule.id",
        "rule.mitre.technique", "rule.mitre.tactic",
        # Network / IPs (ip-typed fields need lenient)
        "agent.ip", "network.srcIp", "network.destIp",
        "data.srcip", "data.dstip", "data.remip", "location",
        # GeoIP / country
        "data.srccountry", "data.dstcountry",
        # Host / agent / device
        "agent.name", "data.devname", "data.hostname", "data.dst_host",
        # Users
        "data.srcuser", "data.dstuser", "data.xauthuser",
        "data.win.eventdata.user", "syscheck.audit.user.name",
        # Actions / events / messages
        "data.action", "data.msg", "data.logdesc",
        "data.subtype", "data.type", "data.status", "data.reason",
        "data.service", "data.group",
        # Application / policy
        "data.app", "data.appcat", "data.policyid",
        # File / URL / process
        "data.filename", "data.url",
        "data.win.eventdata.commandLine", "data.win.eventdata.image",
        "data.win.eventdata.parentImage",
        "data.win.system.message",
        # File integrity
        "syscheck.path", "syscheck.event",
        # Raw log (catches anything not in structured fields)
        "raw_log.message", "raw_log.rule_description",
    ]

    should_clauses = []
    for term in terms:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": _SEARCH_FIELDS,
                "type": "phrase",
                "lenient": True,
            }
        })

    body = {
        "size": effective_size,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                # Mandatory time fence — never query all-time by default
                "filter": [_time_range_filter("@timestamp", hours=effective_hours)],
            }
        },
        # Sort by relevance first, then recency as tiebreaker.
        # Pure recency sort causes low-relevance logs (matching just 1 term)
        # to displace high-relevance logs (matching multiple terms) when the
        # low-relevance log is more recent.
        "sort": [
            {"_score": {"order": "desc"}},
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}},
        ],
    }

    resp = client.search(index=index, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def uba_entity_search(
    terms: list[str],
    size: int = config.TOP_K_VECTORS,
    lookback_days: Optional[int] = None,
) -> list[dict]:
    """
    Keyword search on uba-behavior-summary filtered by entity terms.

    Searches user_id, hostname, summary, and tags fields.  Used to ensure
    entity-specific UBA docs are found even when they are not among the
    top-K nearest neighbors by vector similarity.
    """
    client = get_client()
    effective_days = lookback_days or config.VECTOR_LOOKBACK_DAYS

    should_clauses = []
    for term in terms:
        should_clauses.append({
            "multi_match": {
                "query": term,
                "fields": ["user_id", "hostname", "summary", "tags"],
                "type": "phrase",
            }
        })

    body = {
        "size": size,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": [_time_range_filter("timestamp", days=effective_days)],
            }
        },
        "sort": [{"risk_score": {"order": "desc"}}],
    }

    resp = client.search(index=config.UBA_INDEX, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]


def vector_search(
    query_vector: list[float],
    size: int = config.TOP_K_VECTORS,
    lookback_days: Optional[int] = None,
) -> list[dict]:
    """
    Approximate kNN search on the uba-behavior-summary index with time decay.

    *lookback_days* — only consider summaries newer than this; defaults to
    VECTOR_LOOKBACK_DAYS.  The timestamp filter is applied as a pre-filter
    *before* kNN scoring so old behavioural profiles do not consume any of
    the top-K slots.
    """
    client = get_client()

    effective_days = lookback_days or config.VECTOR_LOOKBACK_DAYS

    # Pre-filter by timestamp, then run kNN within the filtered set.
    # OpenSearch kNN supports a "filter" clause that restricts the
    # candidate pool before similarity scoring.
    body = {
        "size": size,
        "query": {
            "knn": {
                "embedding": {
                    "vector": query_vector,
                    "k": size,
                    "filter": {
                        "range": {
                            "timestamp": {
                                "gte": (
                                    datetime.now(timezone.utc)
                                    - timedelta(days=effective_days)
                                ).isoformat(),
                                "lte": "now",
                            }
                        }
                    },
                }
            }
        },
    }

    resp = client.search(index=config.UBA_INDEX, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]


# ---------------------------------------------------------------------------
# Insight persistence
# ---------------------------------------------------------------------------

def _check_insight_semantic_similarity(query_vector: list[float]) -> float:
    """
    Return the highest cosine similarity between *query_vector* and any
    existing insight in the last VECTOR_LOOKBACK_DAYS.

    Uses the OpenSearch kNN score and converts it back to cosine similarity.
    For lucene cosinesimil space the score formula is:
        score = (1 + cosine_similarity) / 2
    so:
        cosine_similarity = 2 * score - 1

    Returns 0.0 if the index is empty or the search fails.
    """
    client = get_client()
    effective_days = config.VECTOR_LOOKBACK_DAYS

    body = {
        "size": 1,
        "query": {
            "knn": {
                "embedding": {
                    "vector": query_vector,
                    "k": 1,
                    "filter": {
                        "range": {
                            "timestamp": {
                                "gte": (
                                    datetime.now(timezone.utc)
                                    - timedelta(days=effective_days)
                                ).isoformat(),
                                "lte": "now",
                            }
                        }
                    },
                }
            }
        },
    }

    resp = client.search(index=config.INSIGHTS_INDEX, body=body)
    hits = resp["hits"]["hits"]
    if not hits:
        return 0.0

    score = hits[0]["_score"]
    # Convert lucene cosinesimil score back to cosine similarity
    cosine_sim = 2.0 * score - 1.0
    return max(0.0, cosine_sim)


def store_insight(
    question: str,
    answer: str,
    context_hash: str,
    entities_ip: list[str],
    entities_hostname: list[str],
    entities_username: list[str],
    query_vector: list[float],
) -> Optional[str]:
    """
    Persist an LLM-generated insight to uba-insights for future retrieval.

    Two-layer deduplication:
      1. Exact match on context_hash (fast, catches identical contexts).
      2. Semantic similarity via kNN (catches rephrased / near-identical
         insights that differ only because the log window shifted slightly
         or the analyst reworded the question).

    Why both layers are needed in SOC RAG systems:
      Hash dedup alone misses semantic duplicates — two queries about the
      same host at T and T+5min produce different context hashes but
      virtually identical LLM explanations.  Over weeks the insights index
      fills with paraphrases that crowd out diverse knowledge during kNN
      retrieval, reducing the RAG system's analytical breadth.  Semantic
      dedup ensures the index stays information-dense.

    Returns the document _id on success, None if deduplicated away.
    """
    client = get_client()

    # --- Layer 1: exact context hash dedup (cheapest check first) ----------
    dup_check = {
        "size": 1,
        "query": {"term": {"context_hash": context_hash}},
    }
    existing = client.search(index=config.INSIGHTS_INDEX, body=dup_check)
    if existing["hits"]["total"]["value"] > 0:
        logger.debug("Insight dedup (hash) for context_hash=%s", context_hash[:16])
        return None

    # --- Layer 2: semantic similarity dedup --------------------------------
    similarity = _check_insight_semantic_similarity(query_vector)
    if similarity >= config.INSIGHT_SIMILARITY_THRESHOLD:
        logger.debug(
            "Insight dedup (semantic) — cosine_sim=%.4f >= threshold=%.2f",
            similarity,
            config.INSIGHT_SIMILARITY_THRESHOLD,
        )
        return None

    body = {
        "question": question,
        "answer": answer,
        "context_hash": context_hash,
        "entities_ip": entities_ip,
        "entities_hostname": entities_hostname,
        "entities_username": entities_username,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "embedding": query_vector,
    }
    resp = client.index(index=config.INSIGHTS_INDEX, body=body)
    logger.info("Stored insight %s (sim_to_nearest=%.3f)", resp.get("_id"), similarity)
    return resp.get("_id")


def search_insights(
    query_vector: list[float],
    size: int = 2,
    lookback_days: Optional[int] = None,
) -> list[dict]:
    """
    Low-priority kNN search over past insights.

    Used by the retriever to supplement primary retrieval with previously
    generated LLM explanations.  The result set is intentionally small
    (default 2) so insights never dominate the context window.
    """
    client = get_client()

    effective_days = lookback_days or config.VECTOR_LOOKBACK_DAYS

    body = {
        "size": size,
        "query": {
            "knn": {
                "embedding": {
                    "vector": query_vector,
                    "k": size,
                    "filter": {
                        "range": {
                            "timestamp": {
                                "gte": (
                                    datetime.now(timezone.utc)
                                    - timedelta(days=effective_days)
                                ).isoformat(),
                                "lte": "now",
                            }
                        }
                    },
                }
            }
        },
    }

    resp = client.search(index=config.INSIGHTS_INDEX, body=body)
    return [hit["_source"] for hit in resp["hits"]["hits"]]
