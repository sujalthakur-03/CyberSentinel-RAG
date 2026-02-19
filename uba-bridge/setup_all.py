"""
Entry point for one-time setup: creates anomaly detectors and alerting monitors.
Idempotent — safe to run multiple times.
"""

import logging
import time

import requests

import config
from setup_detectors import setup_detectors
from setup_monitors import setup_monitors
from setup_ilm import setup_ilm

logger = logging.getLogger(__name__)


def wait_for_opensearch(max_retries: int = 30, delay: int = 10) -> bool:
    """Wait for OpenSearch to be healthy before proceeding."""
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(
                f"{config.OPENSEARCH_URL}/_cluster/health",
                timeout=10,
            )
            if resp.status_code == 200:
                health = resp.json().get("status", "unknown")
                if health in ("green", "yellow"):
                    logger.info(
                        "OpenSearch is healthy (status=%s) on attempt %d",
                        health, attempt,
                    )
                    return True
                logger.warning(
                    "OpenSearch health=%s on attempt %d, waiting...",
                    health, attempt,
                )
        except requests.ConnectionError:
            logger.info(
                "OpenSearch not reachable (attempt %d/%d), retrying in %ds...",
                attempt, max_retries, delay,
            )
        except Exception:
            logger.exception("Unexpected error checking OpenSearch health")

        time.sleep(delay)

    logger.error("OpenSearch did not become healthy after %d attempts", max_retries)
    return False


def run_setup():
    """Run full setup: wait for OpenSearch, create detectors, create monitors."""
    logger.info("Starting UBA Bridge setup...")

    if not wait_for_opensearch():
        logger.error("Aborting setup — OpenSearch not available")
        return False

    # Small delay after health check to let plugins fully initialize
    time.sleep(5)

    logger.info("Setting up anomaly detectors...")
    detectors = setup_detectors()
    logger.info("Detectors configured: %s", list(detectors.keys()))

    logger.info("Setting up alerting monitors...")
    monitors = setup_monitors()
    logger.info("Monitors configured: %s", list(monitors.keys()))

    logger.info("Setting up index lifecycle management...")
    setup_ilm()

    logger.info("Setup complete. Detectors: %d, Monitors: %d",
                len(detectors), len(monitors))
    return True


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )
    run_setup()
