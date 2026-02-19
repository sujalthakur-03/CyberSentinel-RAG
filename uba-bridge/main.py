"""
CyberSentinel UBA Bridge — FastAPI application.

Bridges OpenSearch anomaly detection and alerting to the RAG service
by polling anomaly results and receiving webhook alerts, enriching them
with log context, and posting behavioral summaries to /index/uba.

Endpoints:
    POST /webhook/alert  — receive alerting webhook notifications
    GET  /health         — liveness / readiness probe
"""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel

import config
from alert_handler import handle_alert
from anomaly_poller import poll_anomaly_results
from setup_all import run_setup

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Track polling task for clean shutdown
_polling_task: asyncio.Task | None = None


async def _polling_loop():
    """Background loop that polls anomaly results at the configured interval."""
    logger.info(
        "Starting anomaly polling loop (interval=%ds)",
        config.POLL_INTERVAL_SECONDS,
    )
    while True:
        try:
            # Run the synchronous poller in a thread to avoid blocking the event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, poll_anomaly_results)
        except Exception:
            logger.exception("Error in anomaly polling loop")

        await asyncio.sleep(config.POLL_INTERVAL_SECONDS)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _polling_task

    logger.info("Starting CyberSentinel UBA Bridge service")

    # Run one-time setup if configured
    if config.SETUP_ON_STARTUP:
        logger.info("Running one-time setup (SETUP_ON_STARTUP=true)...")
        loop = asyncio.get_event_loop()
        success = await loop.run_in_executor(None, run_setup)
        if success:
            logger.info("Setup completed successfully")
        else:
            logger.warning("Setup completed with errors — service will still start")

    # Start the background polling loop
    _polling_task = asyncio.create_task(_polling_loop())

    yield

    # Shutdown: cancel polling
    if _polling_task:
        _polling_task.cancel()
        try:
            await _polling_task
        except asyncio.CancelledError:
            pass
    logger.info("UBA Bridge service shut down")


app = FastAPI(
    title="CyberSentinel UBA Bridge",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------
class AlertWebhookPayload(BaseModel):
    monitor_name: str = ""
    trigger_name: str = ""
    severity: str = "medium"
    entity_type: str = "hostname"
    entity_value: str = "unknown"
    event_count: int = 0
    message: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Basic health check."""
    return {
        "status": "ok",
        "service": "uba-bridge",
        "poll_interval_seconds": config.POLL_INTERVAL_SECONDS,
        "setup_on_startup": config.SETUP_ON_STARTUP,
    }


@app.post("/webhook/alert")
def webhook_alert(payload: AlertWebhookPayload, background_tasks: BackgroundTasks):
    """
    Receive alert webhook from OpenSearch Alerting plugin.

    Processes the alert asynchronously in the background so the webhook
    response is fast (alerting plugin has a short timeout).
    """
    logger.info(
        "Received webhook alert: monitor=%s entity=%s:%s",
        payload.monitor_name,
        payload.entity_type,
        payload.entity_value,
    )

    # Process in background to respond quickly to the webhook
    background_tasks.add_task(handle_alert, payload.model_dump())

    return {
        "status": "accepted",
        "monitor_name": payload.monitor_name,
        "entity": f"{payload.entity_type}:{payload.entity_value}",
    }
