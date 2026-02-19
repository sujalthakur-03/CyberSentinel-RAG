"""
Index lifecycle management for OpenSearch.

Creates ISM policies to auto-delete old indices and cleans up empty tombstone
indices left behind by index rollovers or failed ingestion.
"""

import logging

import requests

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# ISM policy definitions
# ---------------------------------------------------------------------------

LOGS_LIFECYCLE_POLICY = {
    "policy": {
        "description": "Delete logs-* indices older than 90 days",
        "default_state": "open",
        "states": [
            {
                "name": "open",
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "90d",
                        },
                    }
                ],
            },
            {
                "name": "delete",
                "actions": [
                    {"delete": {}},
                ],
                "transitions": [],
            },
        ],
        "ism_template": [
            {
                "index_patterns": ["logs-*"],
                "priority": 100,
            }
        ],
    }
}

ANOMALY_RESULTS_LIFECYCLE_POLICY = {
    "policy": {
        "description": "Delete anomaly result indices older than 7 days",
        "default_state": "open",
        "states": [
            {
                "name": "open",
                "transitions": [
                    {
                        "state_name": "delete",
                        "conditions": {
                            "min_index_age": "7d",
                        },
                    }
                ],
            },
            {
                "name": "delete",
                "actions": [
                    {"delete": {}},
                ],
                "transitions": [],
            },
        ],
        "ism_template": [
            {
                "index_patterns": [".opendistro-anomaly-results-*"],
                "priority": 100,
            }
        ],
    }
}


# ---------------------------------------------------------------------------
# Policy management
# ---------------------------------------------------------------------------

def _put_policy(policy_id: str, body: dict) -> bool:
    """Create or update an ISM policy. Returns True on success."""
    url = f"{config.OPENSEARCH_URL}/_plugins/_ism/policies/{policy_id}"
    # Check if policy already exists
    resp = requests.get(url, timeout=10)
    if resp.status_code == 200:
        # Update: need to include seq_no and primary_term
        existing = resp.json()
        seq_no = existing.get("_seq_no", 0)
        primary_term = existing.get("_primary_term", 1)
        resp = requests.put(
            f"{url}?if_seq_no={seq_no}&if_primary_term={primary_term}",
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
    else:
        # Create
        resp = requests.put(
            url,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

    if resp.status_code in (200, 201):
        logger.info("ISM policy '%s' created/updated successfully", policy_id)
        return True
    else:
        logger.error(
            "Failed to put ISM policy '%s': %s %s",
            policy_id, resp.status_code, resp.text[:300],
        )
        return False


def cleanup_empty_indices():
    """
    Delete indices matching logs-* that have 0 documents (tombstones).
    These are left behind by index rollovers or failed ingestion and
    waste cluster resources.
    """
    try:
        resp = requests.get(
            f"{config.OPENSEARCH_URL}/_cat/indices/logs-*",
            params={"format": "json", "h": "index,docs.count,status"},
            timeout=30,
        )
        resp.raise_for_status()
    except Exception:
        logger.exception("Failed to list logs-* indices for cleanup")
        return

    indices = resp.json()
    deleted = 0
    for idx_info in indices:
        index_name = idx_info.get("index", "")
        doc_count = int(idx_info.get("docs.count", "1") or "1")

        if doc_count == 0:
            try:
                del_resp = requests.delete(
                    f"{config.OPENSEARCH_URL}/{index_name}",
                    timeout=30,
                )
                if del_resp.status_code == 200:
                    logger.info("Deleted empty tombstone index: %s", index_name)
                    deleted += 1
                else:
                    logger.warning(
                        "Failed to delete %s: %s", index_name, del_resp.status_code,
                    )
            except Exception:
                logger.exception("Error deleting tombstone index %s", index_name)

    logger.info("Tombstone cleanup complete: %d empty indices removed", deleted)


def setup_ilm():
    """Create all ISM lifecycle policies and clean up tombstone indices."""
    logger.info("Setting up ISM lifecycle policies...")

    _put_policy("logs-lifecycle", LOGS_LIFECYCLE_POLICY)
    _put_policy("anomaly-results-lifecycle", ANOMALY_RESULTS_LIFECYCLE_POLICY)

    logger.info("Cleaning up empty tombstone indices...")
    cleanup_empty_indices()

    logger.info("ILM setup complete")


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    setup_ilm()
