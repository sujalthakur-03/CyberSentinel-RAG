"""
One-time setup: create anomaly detectors via the OpenSearch Anomaly Detection REST API.

Detectors:
  1. auth-failure-spike      — brute-force / credential-stuffing per source IP
  2. firewall-block-anomaly  — unusual block volume per firewall agent
  3. high-severity-burst     — spikes in high-severity alerts per host
  4. geographic-anomaly      — traffic from unusual countries
  5. endpoint-file-creation  — abnormal file creation activity per host
"""

import logging
import time

import requests

import config

logger = logging.getLogger(__name__)

DETECTORS = [
    {
        "name": "auth-failure-spike",
        "description": "Detect brute-force / credential-stuffing per source IP based on authentication failure counts",
        "indices": ["logs-*"],
        "detection_interval_minutes": 30,
        "feature_attributes": [
            {
                "feature_name": "auth_failure_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "auth_failure_count": {
                        "value_count": {"field": "@timestamp"}
                    }
                },
            }
        ],
        "category_field": ["data.srcip.keyword"],
        "filter_query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "authentication_failed"}}
                ]
            }
        },
    },
    {
        "name": "firewall-block-anomaly",
        "description": "Detect unusual block volume per firewall agent based on firewall drop event counts",
        "indices": ["logs-*"],
        "feature_attributes": [
            {
                "feature_name": "firewall_drop_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "firewall_drop_count": {
                        "value_count": {"field": "@timestamp"}
                    }
                },
            }
        ],
        "category_field": ["agent.name"],
        "filter_query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "firewall_drop"}}
                ]
            }
        },
    },
    {
        "name": "high-severity-burst",
        "description": "Detect sudden spikes in high-severity alerts (rule.level >= 10) per host",
        "indices": ["logs-*"],
        "feature_attributes": [
            {
                "feature_name": "high_severity_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "high_severity_count": {
                        "value_count": {"field": "@timestamp"}
                    }
                },
            }
        ],
        "category_field": ["agent.name"],
        "filter_query": {
            "bool": {
                "filter": [
                    {"range": {"rule.level": {"gte": 10}}}
                ]
            }
        },
    },
    {
        "name": "geographic-anomaly",
        "description": "Detect traffic from unusual countries based on source country distribution",
        "indices": ["logs-*"],
        "feature_attributes": [
            {
                "feature_name": "country_event_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "country_event_count": {
                        "value_count": {"field": "@timestamp"}
                    }
                },
            }
        ],
        "category_field": ["data.srccountry.keyword"],
        "filter_query": {
            "bool": {
                "must": [
                    {"exists": {"field": "data.srccountry"}}
                ]
            }
        },
    },
    {
        "name": "endpoint-file-creation",
        "description": "Detect abnormal file creation activity (Sysmon EID 11) per host as a malware indicator",
        "indices": ["logs-*"],
        "feature_attributes": [
            {
                "feature_name": "file_creation_count",
                "feature_enabled": True,
                "aggregation_query": {
                    "file_creation_count": {
                        "value_count": {"field": "@timestamp"}
                    }
                },
            }
        ],
        "category_field": ["agent.name"],
        "filter_query": {
            "bool": {
                "filter": [
                    {"term": {"rule.groups": "sysmon_eid11_detections"}}
                ]
            }
        },
    },
]


def _build_detector_body(det: dict) -> dict:
    """Build the full detector creation payload."""
    interval_minutes = det.get("detection_interval_minutes", 10)
    return {
        "name": det["name"],
        "description": det["description"],
        "time_field": "@timestamp",
        "indices": det["indices"],
        "feature_attributes": det["feature_attributes"],
        "category_field": det.get("category_field", []),
        "filter_query": det.get("filter_query", {"match_all": {}}),
        "detection_interval": {
            "period": {"interval": interval_minutes, "unit": "Minutes"}
        },
        "window_delay": {
            "period": {"interval": 1, "unit": "Minutes"}
        },
        "shingle_size": 8,
    }


def get_existing_detectors() -> dict[str, str]:
    """Return a mapping of detector name -> detector ID for all existing detectors."""
    body = {
        "query": {"match_all": {}},
        "_source": ["name"],
        "size": 100,
    }
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/_search",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    # 404 means the backing index doesn't exist yet (no detectors ever created)
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    return {hit["_source"]["name"]: hit["_id"] for hit in hits}


def create_detector(det: dict) -> str | None:
    """
    Create a single anomaly detector. Returns the detector ID on success.
    """
    body = _build_detector_body(det)
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 201:
        detector_id = resp.json().get("_id")
        logger.info("Created detector '%s' (ID: %s)", det["name"], detector_id)
        return detector_id
    else:
        logger.error(
            "Failed to create detector '%s': %s %s",
            det["name"], resp.status_code, resp.text,
        )
        return None


def start_detector(detector_id: str, name: str) -> bool:
    """Start an anomaly detector by ID."""
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_start",
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 200:
        logger.info("Started detector '%s' (ID: %s)", name, detector_id)
        return True
    else:
        logger.warning(
            "Failed to start detector '%s': %s %s",
            name, resp.status_code, resp.text,
        )
        return False


def _stop_detector(detector_id: str, name: str) -> bool:
    """Stop an anomaly detector by ID."""
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/{detector_id}/_stop",
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 200:
        logger.info("Stopped detector '%s' (ID: %s)", name, detector_id)
        return True
    else:
        logger.warning(
            "Failed to stop detector '%s': %s %s",
            name, resp.status_code, resp.text,
        )
        return False


def update_detector_if_changed(detector_id: str, det: dict) -> bool:
    """
    Compare running detector config with desired config and update if different.
    Stops the detector, updates it, then restarts it.
    Returns True if an update was performed.
    """
    try:
        resp = requests.get(
            f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/{detector_id}",
            timeout=10,
        )
        if resp.status_code != 200:
            return False

        current = resp.json().get("anomaly_detector", {})
    except Exception:
        logger.exception("Failed to fetch detector %s for comparison", detector_id)
        return False

    desired_body = _build_detector_body(det)

    # Compare detection interval
    current_interval = current.get("detection_interval", {}).get("period", {}).get("interval")
    desired_interval = desired_body["detection_interval"]["period"]["interval"]

    if current_interval == desired_interval:
        return False

    logger.info(
        "Detector '%s' interval changed (%s → %s), updating...",
        det["name"], current_interval, desired_interval,
    )

    # Stop → update → restart
    _stop_detector(detector_id, det["name"])
    time.sleep(1)

    resp = requests.put(
        f"{config.OPENSEARCH_URL}/_plugins/_anomaly_detection/detectors/{detector_id}",
        json=desired_body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 200:
        logger.info("Updated detector '%s'", det["name"])
    else:
        logger.error(
            "Failed to update detector '%s': %s %s",
            det["name"], resp.status_code, resp.text,
        )
        return False

    time.sleep(1)
    start_detector(detector_id, det["name"])
    return True


def setup_detectors() -> dict[str, str]:
    """
    Create and start all anomaly detectors idempotently.
    For existing detectors, checks if config has changed and updates if needed.
    Returns a mapping of detector name -> detector ID.
    """
    existing = get_existing_detectors()
    result = {}

    for det in DETECTORS:
        name = det["name"]
        if name in existing:
            detector_id = existing[name]
            logger.info("Detector '%s' already exists (ID: %s), checking for changes", name, detector_id)
            update_detector_if_changed(detector_id, det)
            result[name] = detector_id
        else:
            detector_id = create_detector(det)
            if detector_id:
                result[name] = detector_id
                # Small delay between creations to avoid overwhelming the API
                time.sleep(1)

    # Start all detectors
    for name, detector_id in result.items():
        start_detector(detector_id, name)
        time.sleep(0.5)

    logger.info("Detector setup complete: %d detectors configured", len(result))
    return result


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    setup_detectors()
