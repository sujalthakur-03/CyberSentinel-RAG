"""
Template-based summary generation from anomaly/alert data + enrichment context.

Produces deterministic, structured behavioral summaries suitable for
indexing into uba-behavior-summary for RAG retrieval.
"""

import logging

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK mappings for common detector types
# ---------------------------------------------------------------------------
DETECTOR_MITRE_MAP = {
    "auth-failure-spike": {"technique": "T1110", "name": "Brute Force"},
    "firewall-block-anomaly": {"technique": "T1071", "name": "Application Layer Protocol"},
    "high-severity-burst": {"technique": "T1059", "name": "Command and Scripting Interpreter"},
    "geographic-anomaly": {"technique": "T1090", "name": "Proxy"},
    "endpoint-file-creation": {"technique": "T1105", "name": "Ingress Tool Transfer"},
}

# ---------------------------------------------------------------------------
# Risk score mapping
# ---------------------------------------------------------------------------

def anomaly_grade_to_risk(grade: float) -> float:
    """Map anomaly grade (0.0-1.0) to risk score (0-100)."""
    return round(min(max(grade * 100, 0), 100), 1)


def alert_severity_to_risk(severity: str) -> float:
    """Map alert severity label to risk score."""
    mapping = {
        "critical": 95.0,
        "high": 80.0,
        "medium": 60.0,
        "low": 40.0,
        "info": 20.0,
    }
    return mapping.get(severity.lower(), 50.0)


# ---------------------------------------------------------------------------
# Tag generation
# ---------------------------------------------------------------------------

def generate_tags(
    detector_name: str = "",
    severity: str = "",
    mitre_techniques: list[str] | None = None,
    alert_type: str = "",
) -> list[str]:
    """Generate tags from detector/alert metadata."""
    tags = ["anomaly"]

    if detector_name:
        # "auth-failure-spike" -> ["auth-failure", "spike"]
        parts = detector_name.split("-")
        tags.extend(parts)

    if detector_name in DETECTOR_MITRE_MAP:
        tags.append(DETECTOR_MITRE_MAP[detector_name]["technique"])

    if mitre_techniques:
        for tech in mitre_techniques:
            if tech not in tags:
                tags.append(tech)

    if severity:
        risk_label = _risk_label(alert_severity_to_risk(severity))
        tags.append(risk_label)

    if alert_type:
        tags.append(alert_type)

    return tags


def _risk_label(score: float) -> str:
    if score >= 80:
        return "high-risk"
    elif score >= 50:
        return "medium-risk"
    return "low-risk"


# ---------------------------------------------------------------------------
# Summary templates
# ---------------------------------------------------------------------------

def build_anomaly_summary(
    detector_name: str,
    entity_value: str,
    anomaly_grade: float,
    feature_value: float,
    enrichment: dict,
) -> str:
    """
    Build a behavioral summary from an anomaly detection result.

    Returns a human-readable paragraph suitable for RAG retrieval.
    """
    risk_score = anomaly_grade_to_risk(anomaly_grade)
    risk_label = _risk_label(risk_score)
    mitre = DETECTOR_MITRE_MAP.get(detector_name, {})

    lines = []

    # Opening line
    lines.append(
        f"Anomaly detected: {detector_name} for entity {entity_value}."
    )

    # Grade and feature value
    lines.append(
        f"Anomaly grade: {anomaly_grade:.2f} ({risk_label}). "
        f"{int(feature_value)} events in detection window."
    )

    # Enrichment: hosts/users
    if enrichment.get("related_hostnames"):
        hosts = ", ".join(enrichment["related_hostnames"][:5])
        lines.append(f"Top targeted hosts: {hosts}.")

    if enrichment.get("related_usernames"):
        users = ", ".join(enrichment["related_usernames"][:5])
        lines.append(f"Top usernames: {users}.")

    # Enrichment: actions
    if enrichment.get("top_actions"):
        actions = ", ".join(enrichment["top_actions"][:5])
        lines.append(f"Top actions: {actions}.")

    # Enrichment: rule descriptions
    if enrichment.get("top_rule_descriptions"):
        rules = "; ".join(enrichment["top_rule_descriptions"][:3])
        lines.append(f"Top rules triggered: {rules}.")

    # MITRE mapping
    techniques = enrichment.get("mitre_techniques", [])
    if mitre:
        techniques = [mitre["technique"]] + [t for t in techniques if t != mitre["technique"]]
    if techniques:
        tech_str = ", ".join(techniques[:5])
        lines.append(f"MITRE ATT&CK: {tech_str}.")

    # Related IPs
    if enrichment.get("related_src_ips"):
        ips = ", ".join(enrichment["related_src_ips"][:5])
        lines.append(f"Related source IPs: {ips}.")

    if enrichment.get("related_dst_ips"):
        ips = ", ".join(enrichment["related_dst_ips"][:5])
        lines.append(f"Related destination IPs: {ips}.")

    # Event count
    if enrichment.get("event_count"):
        lines.append(
            f"Total events in enrichment window: {enrichment['event_count']}."
        )

    return " ".join(lines)


def build_alert_summary(
    monitor_name: str,
    entity_value: str,
    trigger_name: str,
    severity: str,
    results_summary: str,
    enrichment: dict,
) -> str:
    """
    Build a behavioral summary from an alerting monitor trigger.

    Returns a human-readable paragraph suitable for RAG retrieval.
    """
    risk_score = alert_severity_to_risk(severity)
    risk_label = _risk_label(risk_score)

    lines = []

    # Opening line
    lines.append(
        f"Alert triggered: {monitor_name} ({trigger_name}) for entity {entity_value}."
    )
    lines.append(f"Severity: {severity} ({risk_label}). {results_summary}")

    # Enrichment: rule descriptions
    if enrichment.get("top_rule_descriptions"):
        rules = "; ".join(enrichment["top_rule_descriptions"][:3])
        lines.append(f"Top rules triggered: {rules}.")

    # Enrichment: actions
    if enrichment.get("top_actions"):
        actions = ", ".join(enrichment["top_actions"][:5])
        lines.append(f"Top actions observed: {actions}.")

    # MITRE techniques
    techniques = enrichment.get("mitre_techniques", [])
    if techniques:
        tech_str = ", ".join(techniques[:5])
        lines.append(f"MITRE ATT&CK: {tech_str}.")

    # Related IPs
    if enrichment.get("related_src_ips"):
        ips = ", ".join(enrichment["related_src_ips"][:5])
        lines.append(f"Related source IPs: {ips}.")

    if enrichment.get("related_dst_ips"):
        ips = ", ".join(enrichment["related_dst_ips"][:5])
        lines.append(f"Related destination IPs: {ips}.")

    # Hosts and users
    if enrichment.get("related_hostnames"):
        hosts = ", ".join(enrichment["related_hostnames"][:5])
        lines.append(f"Affected hosts: {hosts}.")

    if enrichment.get("related_usernames"):
        users = ", ".join(enrichment["related_usernames"][:5])
        lines.append(f"Related users: {users}.")

    if enrichment.get("event_count"):
        lines.append(
            f"Total events in enrichment window: {enrichment['event_count']}."
        )

    return " ".join(lines)
