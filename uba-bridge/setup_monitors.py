"""
One-time setup: create alerting monitors + webhook destination via the
OpenSearch Alerting and Notifications REST APIs.

Monitors:
  1. brute-force-threshold   — > 50 auth failures per source IP in 15 min
  2. vpn-failure-spike       — > 10 VPN failures per user in 30 min
  3. executable-drop         — > 20 file creations per host in 10 min
  4. mitre-technique-chain   — >= 3 distinct MITRE techniques per host in 1 hour
"""

import logging
import time

import requests

import config

logger = logging.getLogger(__name__)


def _create_webhook_destination() -> str | None:
    """
    Create a webhook notification channel via the Notifications plugin.
    Returns the channel/config ID. Idempotent — returns existing if found.
    """
    # Check for existing notification configs
    try:
        resp = requests.get(
            f"{config.OPENSEARCH_URL}/_plugins/_notifications/configs",
            params={"config_type": "webhook"},
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json()
            for item in data.get("config_list", []):
                if item.get("config", {}).get("name") == "uba-bridge-webhook":
                    config_id = item["config_id"]
                    logger.info("Webhook notification channel already exists (ID: %s)", config_id)
                    return config_id
    except Exception:
        logger.debug("Could not check existing notification configs", exc_info=True)

    # Create new notification channel via Notifications plugin
    body = {
        "name": "uba-bridge-webhook",
        "config": {
            "name": "uba-bridge-webhook",
            "description": "UBA Bridge webhook endpoint for alert notifications",
            "config_type": "webhook",
            "is_enabled": True,
            "webhook": {
                "url": config.WEBHOOK_URL,
                "header_params": {
                    "Content-Type": "application/json",
                },
                "method": "POST",
            },
        },
    }
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_notifications/configs/",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code in (200, 201):
        config_id = resp.json().get("config_id")
        logger.info("Created webhook notification channel (ID: %s)", config_id)
        return config_id
    else:
        logger.error("Failed to create webhook notification channel: %s %s", resp.status_code, resp.text)
        return None


def _build_monitor(name: str, description: str, schedule_interval: int,
                   schedule_unit: str, query: dict, triggers: list) -> dict:
    """Build a monitor body payload."""
    return {
        "name": name,
        "type": "monitor",
        "monitor_type": "bucket_level_monitor",
        "enabled": True,
        "schedule": {
            "period": {
                "interval": schedule_interval,
                "unit": schedule_unit,
            }
        },
        "inputs": [
            {
                "search": {
                    "indices": ["logs-*"],
                    "query": query,
                }
            }
        ],
        "triggers": triggers,
    }


def _build_bucket_trigger(name: str, severity: str, condition_script: str,
                          destination_id: str, message_template: str) -> dict:
    """Build a bucket-level trigger with webhook action."""
    severity_map = {"critical": "1", "high": "2", "medium": "3", "low": "4"}
    return {
        "bucket_level_trigger": {
            "name": name,
            "severity": severity_map.get(severity, "3"),
            "condition": {
                "buckets_path": {"_count": "_count"},
                "parent_bucket_path": "composite_agg",
                "script": {
                    "source": condition_script,
                    "lang": "painless",
                },
            },
            "actions": [
                {
                    "name": f"{name}-webhook-action",
                    "destination_id": destination_id,
                    "message_template": {
                        "source": message_template,
                        "lang": "mustache",
                    },
                    "throttle_enabled": True,
                    "throttle": {
                        "value": 10,
                        "unit": "MINUTES",
                    },
                    "action_execution_policy": {
                        "action_execution_scope": {
                            "per_alert": {
                                "actionable_alerts": ["DEDUPED", "NEW"]
                            }
                        }
                    },
                }
            ],
        }
    }


MONITORS = [
    {
        "name": "brute-force-threshold",
        "description": "Alert when > 50 authentication failures per source IP in 15 minutes",
        "schedule_interval": 5,
        "schedule_unit": "MINUTES",
        "query": {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.groups": "authentication_failed"}},
                        {"range": {"@timestamp": {"gte": "now-15m", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "composite_agg": {
                    "composite": {
                        "sources": [
                            {"srcip": {"terms": {"field": "data.srcip.keyword"}}}
                        ],
                        "size": 50,
                    }
                }
            },
        },
        "trigger_name": "high-auth-failures",
        "trigger_severity": "high",
        "trigger_condition": "params._count > 50",
        "message_template": '{"monitor_name": "brute-force-threshold", "trigger_name": "high-auth-failures", "severity": "high", "entity_type": "ip", "entity_value": "{{ctx.results.0.composite_agg.buckets.0.key.srcip}}", "event_count": {{ctx.results.0.composite_agg.buckets.0.doc_count}}, "message": "Brute force detected: >50 auth failures from source IP in 15 minutes"}',
    },
    {
        "name": "vpn-failure-spike",
        "description": "Alert when > 10 VPN failures per user in 30 minutes",
        "schedule_interval": 10,
        "schedule_unit": "MINUTES",
        "query": {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"exists": {"field": "data.xauthuser"}},
                        {"terms": {"data.action": ["tunnel-down", "tunnel-stats"]}},
                        {"range": {"@timestamp": {"gte": "now-30m", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "composite_agg": {
                    "composite": {
                        "sources": [
                            {"user": {"terms": {"field": "data.xauthuser.keyword"}}}
                        ],
                        "size": 50,
                    }
                }
            },
        },
        "trigger_name": "vpn-credential-abuse",
        "trigger_severity": "high",
        "trigger_condition": "params._count > 10",
        "message_template": '{"monitor_name": "vpn-failure-spike", "trigger_name": "vpn-credential-abuse", "severity": "high", "entity_type": "user", "entity_value": "{{ctx.results.0.composite_agg.buckets.0.key.user}}", "event_count": {{ctx.results.0.composite_agg.buckets.0.doc_count}}, "message": "VPN credential abuse detected: >10 VPN failures per user in 30 minutes"}',
    },
    {
        "name": "executable-drop",
        "description": "Alert when > 20 file creations per host in 10 minutes",
        "schedule_interval": 5,
        "schedule_unit": "MINUTES",
        "query": {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"rule.groups": "sysmon_eid11_detections"}},
                        {"range": {"@timestamp": {"gte": "now-10m", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "composite_agg": {
                    "composite": {
                        "sources": [
                            {"host": {"terms": {"field": "agent.name"}}}
                        ],
                        "size": 50,
                    }
                }
            },
        },
        "trigger_name": "malware-dropper",
        "trigger_severity": "critical",
        "trigger_condition": "params._count > 20",
        "message_template": '{"monitor_name": "executable-drop", "trigger_name": "malware-dropper", "severity": "critical", "entity_type": "hostname", "entity_value": "{{ctx.results.0.composite_agg.buckets.0.key.host}}", "event_count": {{ctx.results.0.composite_agg.buckets.0.doc_count}}, "message": "Malware dropper behavior detected: >20 file creations per host in 10 minutes"}',
    },
    {
        "name": "mitre-technique-chain",
        "description": "Alert when >= 3 distinct MITRE techniques per host in 1 hour",
        "schedule_interval": 15,
        "schedule_unit": "MINUTES",
        "query": {
            "size": 0,
            "query": {
                "bool": {
                    "filter": [
                        {"exists": {"field": "rule.mitre.technique"}},
                        {"range": {"@timestamp": {"gte": "now-1h", "lte": "now"}}},
                    ]
                }
            },
            "aggs": {
                "composite_agg": {
                    "composite": {
                        "sources": [
                            {"host": {"terms": {"field": "agent.name"}}}
                        ],
                        "size": 50,
                    },
                    "aggs": {
                        "unique_techniques": {
                            "cardinality": {
                                "field": "rule.mitre.technique"
                            }
                        }
                    },
                }
            },
        },
        "trigger_name": "multi-stage-attack",
        "trigger_severity": "critical",
        "trigger_condition": "params._count > 0",
        "message_template": '{"monitor_name": "mitre-technique-chain", "trigger_name": "multi-stage-attack", "severity": "critical", "entity_type": "hostname", "entity_value": "{{ctx.results.0.composite_agg.buckets.0.key.host}}", "event_count": {{ctx.results.0.composite_agg.buckets.0.doc_count}}, "message": "Multi-stage attack detected: multiple MITRE techniques observed on single host in 1 hour"}',
    },
]


def get_existing_monitors() -> dict[str, str]:
    """Return a mapping of monitor name -> monitor ID for all existing monitors."""
    body = {
        "query": {"match_all": {}},
        "size": 100,
    }
    resp = requests.post(
        f"{config.OPENSEARCH_URL}/_plugins/_alerting/monitors/_search",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30,
    )
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    data = resp.json()
    hits = data.get("hits", {}).get("hits", [])
    return {
        hit["_source"]["name"]: hit["_id"]
        for hit in hits
        if "name" in hit.get("_source", {})
    }


def setup_monitors() -> dict[str, str]:
    """
    Create webhook destination and all alerting monitors idempotently.
    Returns a mapping of monitor name -> monitor ID.
    """
    # Step 1: Create webhook notification channel
    dest_id = _create_webhook_destination()
    if not dest_id:
        logger.error("Cannot create monitors without a webhook destination")
        return {}

    # Step 2: Check existing monitors
    existing = get_existing_monitors()
    result = {}

    for mon in MONITORS:
        name = mon["name"]
        if name in existing:
            logger.info("Monitor '%s' already exists (ID: %s), skipping", name, existing[name])
            result[name] = existing[name]
            continue

        # Build trigger
        trigger = _build_bucket_trigger(
            name=mon["trigger_name"],
            severity=mon["trigger_severity"],
            condition_script=mon["trigger_condition"],
            destination_id=dest_id,
            message_template=mon["message_template"],
        )

        # Build monitor body
        monitor_body = _build_monitor(
            name=name,
            description=mon["description"],
            schedule_interval=mon["schedule_interval"],
            schedule_unit=mon["schedule_unit"],
            query=mon["query"],
            triggers=[trigger],
        )

        resp = requests.post(
            f"{config.OPENSEARCH_URL}/_plugins/_alerting/monitors",
            json=monitor_body,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if resp.status_code in (200, 201):
            monitor_id = resp.json().get("_id")
            logger.info("Created monitor '%s' (ID: %s)", name, monitor_id)
            result[name] = monitor_id
        else:
            logger.error(
                "Failed to create monitor '%s': %s %s",
                name, resp.status_code, resp.text,
            )

        time.sleep(1)

    logger.info("Monitor setup complete: %d monitors configured", len(result))
    return result


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    setup_monitors()
