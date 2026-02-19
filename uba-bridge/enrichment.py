"""
Enrichment queries against logs-* for entity context.

For each anomaly/alert entity (IP, hostname, or user), queries the last
ENRICHMENT_LOOKBACK_MINUTES of logs to extract rule descriptions, actions,
MITRE techniques, event counts, and related IPs.
"""

import logging
from datetime import datetime, timezone, timedelta

import requests

import config

logger = logging.getLogger(__name__)


def _opensearch_search(body: dict, index: str = config.LOG_INDEX) -> dict:
    """Execute a search against OpenSearch."""
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/{index}/_search",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def enrich_entity(entity_type: str, entity_value: str) -> dict:
    """
    Query logs-* for the last ENRICHMENT_LOOKBACK_MINUTES to build context
    around an entity.

    Parameters:
        entity_type: one of "ip", "hostname", "user"
        entity_value: the entity identifier (e.g. "83.252.200.61")

    Returns a dict with enrichment data:
        - event_count: total events for this entity
        - top_rule_descriptions: top N rule.description values
        - top_actions: top N data.action values
        - mitre_techniques: all distinct rule.mitre.technique values
        - related_src_ips: distinct data.srcip values
        - related_dst_ips: distinct data.dstip values
    """
    field_map = {
        "ip": ["data.srcip.keyword", "data.dstip.keyword", "data.remip.keyword"],
        "hostname": ["agent.name", "data.hostname.keyword", "data.devname.keyword"],
        "user": ["data.srcuser.keyword", "data.dstuser.keyword", "data.xauthuser.keyword"],
    }

    fields = field_map.get(entity_type, ["agent.name"])
    now = datetime.now(timezone.utc)
    gte = (now - timedelta(minutes=config.ENRICHMENT_LOOKBACK_MINUTES)).isoformat()

    # Build should clauses for entity matching
    should_clauses = [
        {"term": {field: entity_value}} for field in fields
    ]

    body = {
        "size": 0,
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1,
                "filter": [
                    {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}
                ],
            }
        },
        "aggs": {
            "top_rules": {
                "terms": {
                    "field": "rule.description.keyword",
                    "size": config.ENRICHMENT_TOP_N,
                }
            },
            "top_actions": {
                "terms": {
                    "field": "data.action",
                    "size": config.ENRICHMENT_TOP_N,
                }
            },
            "mitre_techniques": {
                "terms": {
                    "field": "rule.mitre.technique",
                    "size": 20,
                }
            },
            "src_ips": {
                "terms": {
                    "field": "data.srcip.keyword",
                    "size": 10,
                }
            },
            "dst_ips": {
                "terms": {
                    "field": "data.dstip.keyword",
                    "size": 10,
                }
            },
            "hostnames": {
                "terms": {
                    "field": "agent.name",
                    "size": 10,
                }
            },
            "usernames": {
                "terms": {
                    "field": "data.srcuser.keyword",
                    "size": 10,
                }
            },
        },
    }

    try:
        result = _opensearch_search(body)
    except Exception:
        logger.exception("Enrichment query failed for %s=%s", entity_type, entity_value)
        return _empty_enrichment()

    total = result.get("hits", {}).get("total", {}).get("value", 0)
    aggs = result.get("aggregations", {})

    return {
        "event_count": total,
        "top_rule_descriptions": _extract_keys(aggs.get("top_rules", {})),
        "top_actions": _extract_keys(aggs.get("top_actions", {})),
        "mitre_techniques": _extract_keys(aggs.get("mitre_techniques", {})),
        "related_src_ips": _extract_keys(aggs.get("src_ips", {})),
        "related_dst_ips": _extract_keys(aggs.get("dst_ips", {})),
        "related_hostnames": _extract_keys(aggs.get("hostnames", {})),
        "related_usernames": _extract_keys(aggs.get("usernames", {})),
    }


def enrich_entities_batch(
    entities_by_type: dict[str, list[str]],
) -> dict[tuple[str, str], dict]:
    """
    Batch-enrich multiple entities using one aggregation query per entity type
    instead of N individual queries (~95% reduction in enrichment queries).

    Parameters:
        entities_by_type: mapping of entity_type -> list of entity_values
            e.g. {"ip": ["1.2.3.4", "5.6.7.8"], "hostname": ["web-01"]}

    Returns:
        dict mapping (entity_type, entity_value) -> enrichment dict
    """
    field_map = {
        "ip": ["data.srcip.keyword", "data.dstip.keyword", "data.remip.keyword"],
        "hostname": ["agent.name", "data.hostname.keyword", "data.devname.keyword"],
        "user": ["data.srcuser.keyword", "data.dstuser.keyword", "data.xauthuser.keyword"],
    }

    now = datetime.now(timezone.utc)
    gte = (now - timedelta(minutes=config.ENRICHMENT_LOOKBACK_MINUTES)).isoformat()

    results: dict[tuple[str, str], dict] = {}

    for entity_type, entity_values in entities_by_type.items():
        if not entity_values:
            continue

        fields = field_map.get(entity_type, ["agent.name"])

        # Build a single query matching all entities of this type
        should_clauses = []
        for field in fields:
            should_clauses.append({
                "terms": {field: entity_values}
            })

        # Use a composite aggregation keyed by entity value
        # We group by whichever field matched to get per-entity stats
        entity_aggs = {}
        for field in fields:
            safe_name = field.replace(".", "_")
            entity_aggs[f"by_{safe_name}"] = {
                "terms": {
                    "field": field,
                    "size": len(entity_values) * 2,
                    "include": entity_values,
                },
                "aggs": {
                    "top_rules": {
                        "terms": {
                            "field": "rule.description.keyword",
                            "size": config.ENRICHMENT_TOP_N,
                        }
                    },
                    "top_actions": {
                        "terms": {"field": "data.action", "size": config.ENRICHMENT_TOP_N}
                    },
                    "mitre_techniques": {
                        "terms": {"field": "rule.mitre.technique", "size": 20}
                    },
                    "src_ips": {
                        "terms": {"field": "data.srcip.keyword", "size": 10}
                    },
                    "dst_ips": {
                        "terms": {"field": "data.dstip.keyword", "size": 10}
                    },
                    "hostnames": {
                        "terms": {"field": "agent.name", "size": 10}
                    },
                    "usernames": {
                        "terms": {"field": "data.srcuser.keyword", "size": 10}
                    },
                },
            }

        body = {
            "size": 0,
            "query": {
                "bool": {
                    "should": should_clauses,
                    "minimum_should_match": 1,
                    "filter": [
                        {"range": {"@timestamp": {"gte": gte, "lte": "now"}}}
                    ],
                }
            },
            "aggs": entity_aggs,
        }

        try:
            result = _opensearch_search(body)
        except Exception:
            logger.exception(
                "Batch enrichment query failed for %s entities", entity_type,
            )
            for ev in entity_values:
                results[(entity_type, ev)] = _empty_enrichment()
            continue

        aggs = result.get("aggregations", {})

        # Parse results — merge across field groupings
        entity_data: dict[str, dict] = {ev: None for ev in entity_values}

        for agg_name, agg_result in aggs.items():
            for bucket in agg_result.get("buckets", []):
                entity_val = bucket.get("key", "")
                if entity_val not in entity_data:
                    continue

                enrichment = {
                    "event_count": bucket.get("doc_count", 0),
                    "top_rule_descriptions": _extract_keys(bucket.get("top_rules", {})),
                    "top_actions": _extract_keys(bucket.get("top_actions", {})),
                    "mitre_techniques": _extract_keys(bucket.get("mitre_techniques", {})),
                    "related_src_ips": _extract_keys(bucket.get("src_ips", {})),
                    "related_dst_ips": _extract_keys(bucket.get("dst_ips", {})),
                    "related_hostnames": _extract_keys(bucket.get("hostnames", {})),
                    "related_usernames": _extract_keys(bucket.get("usernames", {})),
                }

                # Merge: keep the result with the higher event count
                existing = entity_data.get(entity_val)
                if existing is None or enrichment["event_count"] > existing.get("event_count", 0):
                    entity_data[entity_val] = enrichment

        for ev in entity_values:
            results[(entity_type, ev)] = entity_data.get(ev) or _empty_enrichment()

    return results


def _extract_keys(agg_result: dict) -> list[str]:
    """Extract bucket keys from a terms aggregation result."""
    buckets = agg_result.get("buckets", [])
    return [b["key"] for b in buckets]


def _empty_enrichment() -> dict:
    """Return an empty enrichment result."""
    return {
        "event_count": 0,
        "top_rule_descriptions": [],
        "top_actions": [],
        "mitre_techniques": [],
        "related_src_ips": [],
        "related_dst_ips": [],
        "related_hostnames": [],
        "related_usernames": [],
    }
