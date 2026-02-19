"""
Processes incoming webhook alerts from the OpenSearch Alerting plugin.
Enriches each alert with log context and posts behavioral summaries
to the RAG service's /index/uba endpoint.
"""

import logging

import requests

import config
from enrichment import enrich_entity
from summary_builder import (
    build_alert_summary,
    alert_severity_to_risk,
    generate_tags,
)

logger = logging.getLogger(__name__)


def handle_alert(payload: dict) -> dict:
    """
    Process a single webhook alert payload from the OpenSearch Alerting plugin.

    Expected payload keys (from the monitor message template):
        - monitor_name: str
        - trigger_name: str
        - severity: str (critical, high, medium, low)
        - entity_type: str (ip, hostname, user)
        - entity_value: str
        - event_count: int
        - message: str

    Returns a dict with processing result.
    """
    monitor_name = payload.get("monitor_name", "unknown")
    trigger_name = payload.get("trigger_name", "unknown")
    severity = payload.get("severity", "medium")
    entity_type = payload.get("entity_type", "hostname")
    entity_value = payload.get("entity_value", "unknown")
    event_count = payload.get("event_count", 0)
    message = payload.get("message", "")

    logger.info(
        "Processing alert: monitor=%s trigger=%s entity=%s:%s count=%d",
        monitor_name, trigger_name, entity_type, entity_value, event_count,
    )

    # Enrich with log context
    enrichment = enrich_entity(entity_type, entity_value)

    # Build results summary from the alert payload
    results_summary = f"{event_count} events detected. {message}"

    # Build the behavioral summary
    summary = build_alert_summary(
        monitor_name=monitor_name,
        entity_value=entity_value,
        trigger_name=trigger_name,
        severity=severity,
        results_summary=results_summary,
        enrichment=enrichment,
    )

    # Calculate risk score and tags
    risk_score = alert_severity_to_risk(severity)
    tags = generate_tags(
        alert_type=monitor_name,
        severity=severity,
        mitre_techniques=enrichment.get("mitre_techniques", []),
    )

    # Determine user_id and hostname
    if entity_type == "ip":
        user_id = entity_value
        hostname = (
            enrichment["related_hostnames"][0]
            if enrichment.get("related_hostnames")
            else ""
        )
    elif entity_type == "user":
        user_id = entity_value
        hostname = (
            enrichment["related_hostnames"][0]
            if enrichment.get("related_hostnames")
            else ""
        )
    else:
        user_id = entity_value
        hostname = entity_value

    # Post to RAG service
    success = _post_to_rag(
        user_id=user_id,
        hostname=hostname,
        summary=summary,
        risk_score=risk_score,
        tags=tags,
    )

    return {
        "status": "processed" if success else "failed",
        "monitor_name": monitor_name,
        "entity": f"{entity_type}:{entity_value}",
        "risk_score": risk_score,
        "posted_to_rag": success,
    }


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
                "Posted alert UBA summary for %s (risk=%.1f)",
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
        logger.exception("Failed to post alert UBA summary for %s", user_id)
        return False
