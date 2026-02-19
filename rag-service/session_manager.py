"""
Short-lived session context for follow-up questions — production v3.

Design constraints (per spec):
 - Stores ONLY summarised context and detected entities — never raw logs.
 - Each session auto-expires after SESSION_TTL_MINUTES of inactivity.
 - No long-term memory, no persistence to disk.
 - Thread-safe: a background reaper evicts stale sessions periodically.

v3 additions — follow-up drift control:
 - Tracks how many consecutive follow-up queries lacked new entities.
 - After FOLLOWUP_ENTITY_RESET_THRESHOLD consecutive empty queries the
   inherited entities are forcibly cleared, preventing "ghost" entity
   inheritance when the analyst has silently pivoted to a new topic.

Usage:
    session_manager.save(session_id, entities, context)
    prev = session_manager.load(session_id)   # None if expired
    session_manager.increment_empty_followups(session_id)
    session_manager.reset_empty_followups(session_id)
"""

import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

import config
from entity_detector import DetectedEntities

logger = logging.getLogger(__name__)


@dataclass
class SessionSnapshot:
    """Snapshot of the last retrieval for a session."""
    entities: DetectedEntities
    context: str               # already-summarised context (never raw logs)
    strategy: str = ""
    created_at: float = field(default_factory=time.monotonic)
    # How many consecutive queries in this session lacked new entities.
    # When this reaches FOLLOWUP_ENTITY_RESET_THRESHOLD the retriever
    # must stop inheriting — the analyst likely moved on.
    consecutive_empty_followups: int = 0


# ---------------------------------------------------------------------------
# In-memory store with TTL
# ---------------------------------------------------------------------------

_store: dict[str, SessionSnapshot] = {}
_lock = threading.Lock()
_TTL_SECONDS: float = config.SESSION_TTL_MINUTES * 60


def save(session_id: str, entities: DetectedEntities, context: str, strategy: str = "") -> None:
    """
    Persist the latest retrieval result for *session_id*.
    Preserves the existing consecutive_empty_followups counter so it
    survives across save cycles (reset only via explicit call).
    """
    with _lock:
        prev = _store.get(session_id)
        prev_count = prev.consecutive_empty_followups if prev else 0
        _store[session_id] = SessionSnapshot(
            entities=entities,
            context=context,
            strategy=strategy,
            consecutive_empty_followups=prev_count,
        )
    logger.debug("Session saved: %s (empty_followups=%d)", session_id, prev_count)


def load(session_id: str) -> Optional[SessionSnapshot]:
    """
    Return the last snapshot for *session_id*, or None if missing/expired.
    Accessing a session does NOT extend its TTL — the SOC analyst must
    issue a real query to refresh context.
    """
    with _lock:
        snap = _store.get(session_id)
    if snap is None:
        return None
    if (time.monotonic() - snap.created_at) > _TTL_SECONDS:
        # Stale — evict inline
        with _lock:
            _store.pop(session_id, None)
        logger.debug("Session expired: %s", session_id)
        return None
    return snap


def increment_empty_followups(session_id: str) -> int:
    """
    Bump the empty-followup counter and return the new value.
    Called by the retriever when a query contained no new entities
    and inheritance was used.
    """
    with _lock:
        snap = _store.get(session_id)
        if snap is None:
            return 0
        snap.consecutive_empty_followups += 1
        return snap.consecutive_empty_followups


def reset_empty_followups(session_id: str) -> None:
    """
    Reset counter to zero.  Called when a query contains fresh entities,
    proving the analyst is still investigating the same topic.
    """
    with _lock:
        snap = _store.get(session_id)
        if snap is not None:
            snap.consecutive_empty_followups = 0


def should_reset_entities(session_id: str) -> bool:
    """
    Return True if the session has exceeded the drift threshold.
    The retriever checks this *before* inheriting entities.
    """
    with _lock:
        snap = _store.get(session_id)
        if snap is None:
            return False
        return snap.consecutive_empty_followups >= config.FOLLOWUP_ENTITY_RESET_THRESHOLD


# ---------------------------------------------------------------------------
# Background reaper
# ---------------------------------------------------------------------------
# Runs every 60 s to prune sessions that nobody re-accessed.
# Keeps memory bounded in long-running deployments.

def _reap() -> None:
    while True:
        time.sleep(60)
        now = time.monotonic()
        expired: list[str] = []
        with _lock:
            for sid, snap in _store.items():
                if (now - snap.created_at) > _TTL_SECONDS:
                    expired.append(sid)
            for sid in expired:
                del _store[sid]
        if expired:
            logger.info("Reaped %d expired sessions", len(expired))


_reaper_thread = threading.Thread(target=_reap, daemon=True, name="session-reaper")
_reaper_thread.start()
