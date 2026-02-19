"""
Polls .opendistro-anomaly-results-* for new anomaly results,
enriches them with log context, builds behavioral summaries,
and posts to the RAG service's /index/uba endpoint.
"""

import logging
import time
from datetime import datetime, timezone, timedelta

import requests

import config
from enrichment import enrich_entity, enrich_entities_batch
from summary_builder import (
    build_anomaly_summary,
    anomaly_grade_to_risk,
    generate_tags,
)

logger = logging.getLogger(__name__)

# In-memory dedup set: maps anomaly result ID -> expiry timestamp
_processed: dict[str, float] = {}


def _cleanup_processed():
    """Remove expired entries from the dedup set."""
    now = time.time()
    expired = [k for k, v in _processed.items() if v < now]
    for k in expired:
        del _processed[k]


def _is_processed(result_id: str) -> bool:
    """Check if an anomaly result has already been processed."""
    _cleanup_processed()
    return result_id in _processed


def _mark_processed(result_id: str):
    """Mark an anomaly result as processed with TTL."""
    _processed[result_id] = time.time() + config.DEDUP_TTL_SECONDS


def _detect_entity(result: dict) -> tuple[str, str]:
    """
    Extract entity type and value from an anomaly result.
    Returns (entity_type, entity_value).
    """
    entity = result.get("entity", [])
    if entity:
        # Entity is a list of dicts with "name" and "value"
        first = entity[0] if isinstance(entity, list) else entity
        if isinstance(first, dict):
            field_name = first.get("name", "")
            value = first.get("value", "unknown")
        else:
            field_name = ""
            value = str(first)

        # Map field names to entity types
        if "srcip" in field_name or "dstip" in field_name or "remip" in field_name:
            return "ip", value
        elif "user" in field_name.lower():
            return "user", value
        else:
            return "hostname", value

    return "hostname", "unknown"


def poll_anomaly_results():
    """
    Query for recent anomaly results and process new ones.
    Called periodically by the scheduler.
    """
    logger.info("Polling for anomaly results...")

    # Query for anomaly results from the last poll interval + buffer
    lookback_minutes = max(config.POLL_INTERVAL_SECONDS // 60 + 5, 15)
    gte = (
        datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    ).isoformat()

    body = {
        "size": config.POLL_BATCH_SIZE,
        "query": {
            "bool": {
                "filter": [
                    {"range": {"data_start_time": {"gte": gte}}},
                    # Only get results with actual anomalies (grade > 0)
                    {"range": {"anomaly_grade": {"gt": 0}}},
                ],
            }
        },
        "sort": [{"data_start_time": {"order": "desc"}}],
    }

    try:
        resp = requests.post(
            f"{config.OPENSEARCH_URL}/{config.ANOMALY_RESULTS_INDEX}/_search",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
    except Exception:
        logger.exception("Failed to query anomaly results")
        return

    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    total_available = data.get("hits", {}).get("total", {}).get("value", 0)
    logger.info("Found %d anomaly results (total available: %d)", len(hits), total_available)

    if total_available > config.POLL_BATCH_SIZE:
        logger.warning(
            "Anomaly results truncated: %d available but batch size is %d",
            total_available, config.POLL_BATCH_SIZE,
        )

    # --- Pass 1: Collect anomalies that need processing ---
    to_process: list[dict] = []
    for hit in hits:
        result_id = hit["_id"]
        if _is_processed(result_id):
            continue

        source = hit["_source"]
        anomaly_grade = source.get("anomaly_grade", 0)

        # Skip low-grade anomalies (noise) — raised from 0.3 to 0.5
        if anomaly_grade < 0.5:
            _mark_processed(result_id)
            continue

        detector_id = source.get("detector_id", "unknown")
        entity_type, entity_value = _detect_entity(source)
        detector_name = _get_detector_name(detector_id)

        feature_data = source.get("feature_data", [])
        feature_value = 0.0
        if feature_data:
            feature_value = feature_data[0].get("data", 0.0)

        to_process.append({
            "result_id": result_id,
            "anomaly_grade": anomaly_grade,
            "detector_name": detector_name,
            "entity_type": entity_type,
            "entity_value": entity_value,
            "feature_value": feature_value,
        })

    if not to_process:
        logger.info("No new anomalies above grade threshold to process")
        return

    # --- Batch enrichment: 1 query per entity type instead of N individual queries ---
    entities_by_type: dict[str, list[str]] = {}
    for item in to_process:
        etype = item["entity_type"]
        evalue = item["entity_value"]
        entities_by_type.setdefault(etype, [])
        if evalue not in entities_by_type[etype]:
            entities_by_type[etype].append(evalue)

    batch_enrichments = enrich_entities_batch(entities_by_type)

    # --- Pass 2: Build summaries and post to RAG ---
    processed_count = 0
    for item in to_process:
        entity_key = (item["entity_type"], item["entity_value"])
        enrichment = batch_enrichments.get(entity_key, {})

        summary = build_anomaly_summary(
            detector_name=item["detector_name"],
            entity_value=item["entity_value"],
            anomaly_grade=item["anomaly_grade"],
            feature_value=item["feature_value"],
            enrichment=enrichment,
        )

        risk_score = anomaly_grade_to_risk(item["anomaly_grade"])
        tags = generate_tags(
            detector_name=item["detector_name"],
            mitre_techniques=enrichment.get("mitre_techniques", []),
        )

        entity_type = item["entity_type"]
        entity_value = item["entity_value"]

        if entity_type in ("ip", "user"):
            user_id = entity_value
            hostname = enrichment.get("related_hostnames", [""])[0] if enrichment.get("related_hostnames") else ""
        else:
            user_id = entity_value
            hostname = entity_value

        success = _post_to_rag(
            user_id=user_id,
            hostname=hostname,
            summary=summary,
            risk_score=risk_score,
            tags=tags,
        )

        if success:
            processed_count += 1

        _mark_processed(item["result_id"])

    logger.info("Processed %d new anomaly results", processed_count)


# Cache: detector_id -> detector_name
_detector_name_cache: dict[str, str] = {}


def _get_detector_name(detector_id: str) -> str:
    """Look up detector name by ID, with caching."""
    if detector_id in _detector_name_cache:
        return _detector_name_cache[detector_id]

    try:
        resp = requests.get(
            f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/{detector_id}",
            timeout=10,
        )
        if resp.status_code == 200:
            name = resp.json().get("anomaly_detector", {}).get("name", detector_id)
            _detector_name_cache[detector_id] = name
            return name
    except Exception:
        logger.debug("Could not look up detector name for %s", detector_id)

    return detector_id


def _post_to_rag(
    user_id: str,
    hostname: str,
    summary: str,
    risk_score: float,
    tags: list[str],
) -> bool:
    """Post a behavioral summary to the RAG service's /index/uba endpoint."""
    payload = {
        "user_id": user_id,
        "hostname": hostname,
        "summary": summary,
        "risk_score": risk_score,
        "tags": tags,
    }

    try:
        resp = requests.post(
            f"{config.RAG_SERVICE_URL}/index/uba",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code == 201:
            logger.info(
                "Posted UBA summary for %s (risk=%.1f)",
                user_id, risk_score,
            )
            return True
        else:
            logger.warning(
                "RAG /index/uba returned %s: %s",
                resp.status_code, resp.text[:200],
            )
            return False
    except Exception:
        logger.exception("Failed to post UBA summary for %s", user_id)
        return False
