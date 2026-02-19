"""
Retrieval orchestrator — production v4.

Responsibilities:
  1. Route queries to keyword search (logs-*) and/or kNN vector search
     (uba-behavior-summary) based on detected entities.
  2. Apply mandatory time-range filters to every search.
  3. Execute independent retrieval sources in PARALLEL for low latency.
  4. Aggregate raw hits into structured, de-duplicated context blocks
     grouped by IP / hostname (logs) or merged by similarity (UBA).
  5. Support follow-up questions via short-lived session context with
     drift control (auto-reset after N consecutive empty queries).
  6. Classify risk using PERCENTILE-BASED ranking (adaptive to current
     alert distribution) with absolute threshold as fallback.
  7. Order final context by risk priority.
  8. Enforce context size limits before anything reaches the LLM.

Retrieval flow diagram:

  ┌──────────────┐
  │  User Query   │
  └──────┬───────┘
         │
         ▼
  ┌──────────────────┐
  │ Entity Detection  │  IPs, hosts, users, time range, behavioral flag
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────┐
  │  Session Drift    │  Inherit entities from session if current query
  │  Control          │  is empty — up to RESET_THRESHOLD, then force-clear.
  └──────┬───────────┘
         │
         ▼
  ┌──────────────────────────────────────────────────────┐
  │  PARALLEL RETRIEVAL  (ThreadPoolExecutor, max_workers=3)        │
  │                                                                  │
  │  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐ │
  │  │ Keyword Search   │  │ Vector Search   │  │ Insight Search  │ │
  │  │ logs-* + time    │  │ uba-behavior-   │  │ uba-insights    │ │
  │  │ fence + cap      │  │ summary + decay │  │ (2 results)     │ │
  │  └────────┬────────┘  └────────┬────────┘  └────────┬────────┘ │
  │           │                    │                     │          │
  └───────────┼────────────────────┼─────────────────────┼──────────┘
              │                    │                     │
              ▼                    ▼                     ▼
  ┌──────────────────────────────────────────────────────────────┐
  │  RISK-CALIBRATED CONTEXT ASSEMBLY                             │
  │                                                               │
  │  Risk classification:                                         │
  │    if N ≥ MIN_SAMPLES: top (1-RISK_PERCENTILE_THRESHOLD)%    │
  │    else:               absolute threshold (70.0)              │
  │                                                               │
  │  Priority order:                                              │
  │    1) High-risk UBA  (top percentile or ≥ 70)                │
  │    2) Aggregated logs (by recency)                            │
  │    3) Lower-risk UBA (supporting context)                     │
  │    4) Past insights  (supplementary, max 2)                   │
  └──────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                      Bounded context → LLM

  Timing: each retrieval source logs its wall-clock duration independently
  for latency observability.  Total parallel time ≈ max(individual times).
"""

import logging
import time as _time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from typing import Optional

import config
import embedding
import opensearch_client
import query_rewriter
import session_manager
from entity_detector import DetectedEntities, detect_entities

logger = logging.getLogger(__name__)

# Stop words to exclude when extracting search terms from free-text queries.
_STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "shall",
    "should", "may", "might", "must", "can", "could",
    "i", "me", "my", "we", "our", "you", "your", "he", "she", "it",
    "they", "them", "their", "this", "that", "these", "those",
    "what", "which", "who", "whom", "where", "when", "how", "why",
    "and", "or", "but", "if", "then", "so", "because", "as", "of",
    "in", "on", "at", "to", "for", "with", "by", "from", "about",
    "into", "through", "during", "before", "after", "above", "below",
    "between", "under", "again", "further", "any", "all", "each",
    "every", "both", "few", "more", "most", "other", "some", "such",
    "no", "not", "only", "own", "same", "than", "too", "very",
    "show", "find", "get", "list", "display", "give", "tell",
    "recent", "latest", "last", "there", "here",
})


def _extract_query_terms(query: str) -> list[str]:
    """
    Extract meaningful search terms from a free-text query when no
    structured entities (IPs, hostnames, usernames) are detected.

    Filters out common English stop words and keeps terms that are
    likely to match log field values (rule descriptions, actions,
    device names, event types, etc.).
    """
    import re
    words = re.findall(r"[a-zA-Z0-9._@:/-]+", query)
    terms = [w for w in words if w.lower() not in _STOP_WORDS and len(w) >= 2]
    return terms


# Absolute risk score threshold — used as fallback when there are too few
# UBA results for meaningful percentile calculation.
_HIGH_RISK_THRESHOLD = 70.0


@dataclass
class RetrievalResult:
    strategy: str                # "keyword" | "vector" | "hybrid" | "keyword_fallback" | "session_followup"
    raw_hits: list[dict]
    context: str                 # structured summary sent to the LLM
    entities: DetectedEntities
    session_id: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════
# STRUCTURED CONTEXT AGGREGATION
# ═══════════════════════════════════════════════════════════════════════════
#
# Log aggregation operates on a bounded result set (≤ MAX_LOG_HITS_PER_QUERY)
# sorted by @timestamp desc from OpenSearch.  Because the most-recent events
# are returned first, the aggregated counts and timeframe boundaries
# accurately represent the *recent* activity profile, which is what SOC
# triage needs.  This is a statistical sample, not an exhaustive count —
# exhaustive forensic evidence collection is handled downstream by DFIR
# tooling querying OpenSearch directly.

_SKIP_FIELDS = frozenset({
    "embedding", "vector", "_score", "message_raw", "raw_log",
})


def _get_nested(doc: dict, path: str):
    """Safely retrieve a nested field like 'network.srcIp' from a dict."""
    parts = path.split(".")
    val = doc
    for p in parts:
        if isinstance(val, dict):
            val = val.get(p)
        else:
            return None
    return val


def _pick_grouping_key(doc: dict, intent: str = "general") -> str:
    """
    Determine the best grouping axis for a log document.
    Supports both nested (Wazuh/Fortigate) and flat field schemas.

    For aggregate queries about agents/hosts, prioritises agent.name
    over IP fields so logs group by agent for ranking questions.
    """
    if intent == "aggregate":
        # Agent/host-first ordering for aggregate queries
        candidates = [
            "agent.name", "data.devname", "agent.ip",
            "network.srcIp", "data.remip", "network.destIp",
            "location", "source_ip", "dest_ip", "hostname",
            "src_host", "dst_host",
        ]
    else:
        candidates = [
            "network.srcIp", "data.remip", "network.destIp",
            "agent.ip", "location", "agent.name", "data.devname",
            "source_ip", "dest_ip", "hostname", "src_host", "dst_host",
        ]
    for f in candidates:
        val = _get_nested(doc, f)
        if val and str(val) not in ("unknown", "N/A", "null", ""):
            return str(val)
    return "unknown"


def _aggregate_logs(hits: list[dict], intent: str = "general") -> list[str]:
    """
    Group log hits by IP/hostname and produce compact analytical blocks
    that include key field details so the LLM can answer questions about
    any field present in the raw logs.

    Input is already bounded to MAX_LOG_HITS_PER_QUERY and sorted by
    recency, so aggregation CPU cost is predictable and the resulting
    counts/timeframes reflect the most recent activity window.
    """
    groups: dict[str, list[dict]] = defaultdict(list)
    for doc in hits:
        key = _pick_grouping_key(doc, intent=intent)
        groups[key].append(doc)

    # Fields to extract unique values from, for inclusion in context.
    # Covers network, identity, policy, application, MITRE, and message fields.
    _DETAIL_FIELDS = [
        ("rule.id", "rule_ids"),
        ("rule.level", "rule_levels"),
        ("rule.groups", "rule_groups"),
        ("rule.mitre.technique", "mitre_techniques"),
        ("rule.mitre.tactic", "mitre_tactics"),
        ("data.policyid", "policy_ids"),
        ("data.action", "actions"),
        ("data.service", "services"),
        ("data.app", "apps"),
        ("data.hostname", "dest_hostnames"),
        ("data.srcip", "src_ips"),
        ("data.dstip", "dst_ips"),
        ("data.srcport", "src_ports"),
        ("data.dstport", "dst_ports"),
        ("data.srccountry", "src_countries"),
        ("data.dstcountry", "dst_countries"),
        ("data.srcintf", "src_interfaces"),
        ("data.dstintf", "dst_interfaces"),
        ("data.msg", "messages"),
        ("data.logdesc", "log_descs"),
        ("data.subtype", "subtypes"),
        ("data.type", "types"),
        ("data.status", "statuses"),
        ("data.reason", "reasons"),
        ("data.url", "urls"),
        ("network.srcPort", "src_ports"),
        ("network.destPort", "dst_ports"),
        ("network.protocol", "protocols"),
        ("agent.name", "agent_names"),
        ("agent.ip", "agent_ips"),
        ("data.devname", "device_names"),
        ("data.xauthuser", "vpn_users"),
        ("syscheck.path", "file_paths"),
        ("syscheck.event", "fim_events"),
    ]

    blocks: list[str] = []
    for group_key, docs in groups.items():
        event_counts: dict[str, int] = defaultdict(int)
        timestamps: list[str] = []
        users: set[str] = set()
        detail_values: dict[str, set[str]] = defaultdict(set)

        for d in docs:
            # Event type — try nested paths then flat
            evt = (
                _get_nested(d, "rule.description")
                or _get_nested(d, "data.action")
                or d.get("event_type")
                or d.get("action")
                or "event"
            )
            event_counts[evt] += 1

            ts = d.get("@timestamp") or d.get("timestamp")
            if ts:
                timestamps.append(str(ts))

            # Users — nested + flat
            for uf in ("data.srcuser", "data.dstuser", "data.xauthuser",
                        "user", "username", "user_id"):
                u = _get_nested(d, uf)
                if u and str(u) not in ("", "unknown", "N/A"):
                    users.add(str(u))

            # Extract all detail fields
            for field_path, label in _DETAIL_FIELDS:
                val = _get_nested(d, field_path)
                if val is None or str(val) in ("", "null", "N/A"):
                    continue
                # Handle list values (e.g. rule.groups, mitre.technique)
                if isinstance(val, list):
                    for v in val:
                        if v and str(v).strip():
                            detail_values[label].add(str(v))
                else:
                    detail_values[label].add(str(val))

        lines = [f"IP/Host {group_key}:"]
        for evt, cnt in sorted(event_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  - {cnt} × {evt}")
        if users:
            lines.append(f"  - users: {', '.join(sorted(users))}")
        if timestamps:
            timestamps.sort()
            lines.append(f"  - timeframe: {timestamps[0]} → {timestamps[-1]}")

        # Append detail fields (skip fields already shown or redundant
        # with the grouping key)
        _SKIP_LABELS = {"agent_names", "agent_ips", "device_names"}
        for label, vals in sorted(detail_values.items()):
            if label in _SKIP_LABELS:
                continue
            # Limit to 10 unique values to avoid context explosion
            sorted_vals = sorted(vals)
            if len(sorted_vals) > 10:
                sorted_vals = sorted_vals[:10] + [f"...+{len(vals)-10} more"]
            lines.append(f"  - {label}: {', '.join(sorted_vals)}")

        blocks.append("\n".join(lines))

    return blocks


def _compute_risk_cutoff(scores: list[float]) -> float:
    """
    Compute the risk score value at the configured percentile boundary.

    If there are enough samples (≥ RISK_PERCENTILE_MIN_SAMPLES), use
    percentile-based ranking — the top (1 - RISK_PERCENTILE_THRESHOLD)%
    of scores are classified as high-risk.

    Otherwise fall back to the absolute _HIGH_RISK_THRESHOLD.

    SOC reasoning:
      Risk significance is relative to the current environment activity.
      A score of 65 may be the highest in a quiet week but unremarkable
      during a noisy incident.  Percentile ranking adapts automatically,
      ensuring the LLM always prioritises the most anomalous signals
      relative to what was actually retrieved — not to an arbitrary number
      that may drift out of calibration as detection rules evolve.
    """
    if len(scores) < config.RISK_PERCENTILE_MIN_SAMPLES:
        return _HIGH_RISK_THRESHOLD

    sorted_scores = sorted(scores)
    # Index at the percentile boundary (e.g. 80th percentile of 10 → index 8)
    idx = int(len(sorted_scores) * config.RISK_PERCENTILE_THRESHOLD)
    # Clamp to valid range
    idx = min(idx, len(sorted_scores) - 1)
    percentile_cutoff = sorted_scores[idx]

    # Never classify everything as high-risk: if the percentile cutoff
    # falls below the absolute threshold, use the absolute threshold instead.
    # This prevents low-noise periods from inflating minor scores.
    return max(percentile_cutoff, _HIGH_RISK_THRESHOLD)


def _aggregate_uba(hits: list[dict]) -> tuple[list[str], list[str]]:
    """
    Merge and de-duplicate UBA behavioural summaries.

    Returns two lists:
      (high_risk_blocks, low_risk_blocks)

    Classification uses percentile-based risk ranking when enough samples
    exist, with an absolute threshold fallback.  This makes the high/low
    split adaptive to the current alert distribution.
    """
    merged: dict[tuple, dict] = {}

    for doc in hits:
        uid = doc.get("user_id", "unknown")
        tags = frozenset(doc.get("tags", []))
        key = (uid, tags)

        if key not in merged:
            merged[key] = {
                "user_id": uid,
                "hostname": doc.get("hostname", ""),
                "summaries": [],
                "risk_score": 0.0,
                "tags": sorted(tags),
            }

        entry = merged[key]
        summary_text = doc.get("summary", "")
        if summary_text and summary_text not in entry["summaries"]:
            entry["summaries"].append(summary_text)
        entry["risk_score"] = max(entry["risk_score"], doc.get("risk_score", 0.0))

    # --- Percentile-based risk classification -----------------------------
    all_scores = [e["risk_score"] for e in merged.values()]
    cutoff = _compute_risk_cutoff(all_scores)
    logger.debug(
        "Risk cutoff=%.1f (from %d samples, percentile=%.0f%%, abs_fallback=%.1f)",
        cutoff, len(all_scores),
        config.RISK_PERCENTILE_THRESHOLD * 100,
        _HIGH_RISK_THRESHOLD,
    )

    high: list[str] = []
    low: list[str] = []

    for entry in sorted(merged.values(), key=lambda e: -e["risk_score"]):
        lines = [f"User {entry['user_id']}  (risk: {entry['risk_score']:.1f})"]
        if entry["hostname"]:
            lines[0] += f"  host: {entry['hostname']}"
        for s in entry["summaries"]:
            lines.append(f"  - {s}")
        if entry["tags"]:
            lines.append(f"  tags: {', '.join(entry['tags'])}")
        block = "\n".join(lines)

        if entry["risk_score"] >= cutoff:
            high.append(block)
        else:
            low.append(block)

    return high, low


def _format_insights(hits: list[dict]) -> list[str]:
    """
    Format past insight documents into compact reference blocks.
    These are low-priority supplements — not primary evidence.
    """
    blocks: list[str] = []
    seen_hashes: set[str] = set()
    for doc in hits:
        ch = doc.get("context_hash", "")
        if ch in seen_hashes:
            continue
        seen_hashes.add(ch)

        q = doc.get("question", "")
        a = doc.get("answer", "")
        # Truncate long past answers to keep context budget reasonable
        if len(a) > 300:
            a = a[:300] + "…"
        blocks.append(f"Previous analysis (Q: {q}):\n  {a}")
    return blocks


def _build_context(
    log_hits: list[dict],
    uba_hits: list[dict],
    insight_hits: list[dict],
    intent: str = "general",
) -> str:
    """
    Assemble the final context string with risk-aware ordering and
    intent-aware dynamic budget.

    Dynamic budget by intent:
      intent              | log blocks | high UBA | low UBA
      aggregate           |     7      |    1     |    0
      behavioral          |     2      |    4     |    2
      entity_investigation|     4      |    2     |    1
      general             |     4      |    2     |    1

    For aggregate intent, UBA blocks whose entity already appears in
    log blocks are suppressed to avoid duplication.  For other intents,
    log blocks get a one-liner UBA risk annotation instead of full UBA block.
    """
    # Intent-aware block budgets
    _BUDGETS = {
        "aggregate":            {"log": 7, "high_uba": 1, "low_uba": 0},
        "behavioral":           {"log": 2, "high_uba": 4, "low_uba": 2},
        "entity_investigation": {"log": 4, "high_uba": 2, "low_uba": 1},
        "general":              {"log": 4, "high_uba": 2, "low_uba": 1},
    }
    budget = _BUDGETS.get(intent, _BUDGETS["general"])

    sections: list[str] = []

    # --- 1. High-risk UBA (top of context = highest LLM attention) --------
    high_uba, low_uba = _aggregate_uba(uba_hits)

    # For aggregate intent: collect entity names from log blocks to
    # suppress duplicate UBA blocks later
    log_blocks = _aggregate_logs(log_hits, intent=intent)
    log_entity_names: set[str] = set()
    if intent == "aggregate" and log_blocks:
        for block in log_blocks:
            # Extract entity from "IP/Host <entity>:" header line
            first_line = block.split("\n", 1)[0]
            if first_line.startswith("IP/Host "):
                entity_name = first_line[len("IP/Host "):].rstrip(":")
                log_entity_names.add(entity_name.lower())

    # Build UBA risk lookup for annotation (non-aggregate intents)
    uba_risk_lookup: dict[str, float] = {}
    for doc in uba_hits:
        uid = doc.get("user_id", "")
        risk = doc.get("risk_score", 0.0)
        if uid:
            uba_risk_lookup[uid.lower()] = max(
                uba_risk_lookup.get(uid.lower(), 0.0), risk,
            )

    if high_uba and budget["high_uba"] > 0:
        if intent == "aggregate":
            # Suppress UBA blocks whose entity is already in log blocks
            filtered = [
                b for b in high_uba
                if not any(
                    name in b.lower() for name in log_entity_names
                )
            ]
            limited = filtered[: budget["high_uba"]]
        else:
            limited = high_uba[: budget["high_uba"]]
        if limited:
            sections.append(
                "=== High-Risk Behavioral Alerts ===\n" + "\n\n".join(limited)
            )

    # --- 2. Recent log activity -------------------------------------------
    if log_blocks:
        # For non-aggregate intents, annotate log blocks with UBA risk one-liner
        if intent != "aggregate" and uba_risk_lookup:
            annotated_blocks = []
            for block in log_blocks:
                first_line = block.split("\n", 1)[0]
                if first_line.startswith("IP/Host "):
                    entity_name = first_line[len("IP/Host "):].rstrip(":")
                    risk = uba_risk_lookup.get(entity_name.lower())
                    if risk is not None and risk > 0:
                        block = block + f"\n  [UBA risk: {risk:.1f}]"
                annotated_blocks.append(block)
            limited = annotated_blocks[: budget["log"]]
        else:
            limited = log_blocks[: budget["log"]]
        sections.append("=== Log Activity ===\n" + "\n\n".join(limited))

    # --- 3. Lower-risk UBA ------------------------------------------------
    if low_uba and budget["low_uba"] > 0:
        limited = low_uba[: budget["low_uba"]]
        sections.append(
            "=== Supporting Behavioral Context ===\n" + "\n\n".join(limited)
        )

    # --- 4. Past insights (supplementary) ---------------------------------
    has_primary_data = bool(log_hits or uba_hits)
    if has_primary_data:
        insight_blocks = _format_insights(insight_hits)
        if insight_blocks:
            limited = insight_blocks[:2]
            sections.append(
                "=== Past Analysis Reference ===\n" + "\n\n".join(limited)
            )

    text = "\n\n".join(sections)
    if len(text) > config.MAX_CONTEXT_CHARS:
        text = text[: config.MAX_CONTEXT_CHARS] + "\n[…truncated]"
    return text


# ═══════════════════════════════════════════════════════════════════════════
# TIMED RETRIEVAL HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _timed_keyword_search(
    terms: list[str], lookback_hours: int, size: int = config.TOP_K_LOGS,
) -> list[dict]:
    """Keyword search wrapper that logs wall-clock duration."""
    t0 = _time.monotonic()
    hits = opensearch_client.keyword_search(
        terms, lookback_hours=lookback_hours, size=size,
    )
    elapsed = (_time.monotonic() - t0) * 1000
    logger.info("keyword_search returned %d hits in %.1f ms", len(hits), elapsed)
    return hits


def _timed_vector_search(query_vec: list[float]) -> list[dict]:
    """Vector search wrapper that logs wall-clock duration."""
    t0 = _time.monotonic()
    hits = opensearch_client.vector_search(
        query_vec, lookback_days=config.VECTOR_LOOKBACK_DAYS,
    )
    elapsed = (_time.monotonic() - t0) * 1000
    logger.info("vector_search returned %d hits in %.1f ms", len(hits), elapsed)
    return hits


def _timed_uba_entity_search(terms: list[str]) -> list[dict]:
    """Entity-targeted keyword search on UBA index with timing."""
    t0 = _time.monotonic()
    hits = opensearch_client.uba_entity_search(
        terms, lookback_days=config.VECTOR_LOOKBACK_DAYS,
    )
    elapsed = (_time.monotonic() - t0) * 1000
    logger.info("uba_entity_search returned %d hits in %.1f ms", len(hits), elapsed)
    return hits


def _timed_insight_search(query_vec: list[float]) -> list[dict]:
    """Insight search wrapper — returns empty list on failure (supplementary)."""
    t0 = _time.monotonic()
    try:
        hits = opensearch_client.search_insights(
            query_vec, size=2, lookback_days=config.VECTOR_LOOKBACK_DAYS,
        )
    except Exception:
        # Insights are supplementary — never fail the main pipeline
        logger.debug("Insight search failed (index may not exist yet)")
        hits = []
    elapsed = (_time.monotonic() - t0) * 1000
    logger.info("insight_search returned %d hits in %.1f ms", len(hits), elapsed)
    return hits


# ═══════════════════════════════════════════════════════════════════════════
# MAIN RETRIEVAL PIPELINE
# ═══════════════════════════════════════════════════════════════════════════

def retrieve(query: str, session_id: Optional[str] = None) -> RetrievalResult:
    """
    End-to-end retrieval pipeline:
      1. Detect entities and time range in the query.
      2. Follow-up drift control.
      3. Execute applicable searches IN PARALLEL (keyword, vector, insight).
      4. Aggregate results with percentile-based risk classification.
      5. Assemble risk-prioritised context.
      6. Save session snapshot (summarised context only — never raw logs).

    Parallelism rationale:
      In production, each OpenSearch query takes 10–200 ms depending on
      index size and shard count.  Running keyword + vector + insight
      searches sequentially means worst-case 600 ms of I/O wait.
      ThreadPoolExecutor runs them concurrently so total wall-clock ≈
      max(individual times).

    Determinism guarantee:
      Futures are collected in fixed order (keyword → vector → insight).
      Context assembly applies the same risk-ordering rules regardless
      of which future completes first.  No race-condition-based ordering.
    """
    t0_total = _time.monotonic()

    # ------------------------------------------------------------------
    # Query rewriting — fix spelling/grammar before entity detection
    # ------------------------------------------------------------------
    original_query = query
    query = query_rewriter.rewrite_query(query)

    entities = detect_entities(query)
    logger.info(
        "Entities — IPs: %s, hosts: %s, users: %s, behavioral: %s, "
        "time_range_hours: %s, intent: %s",
        entities.ips, entities.hostnames, entities.usernames,
        entities.is_behavioral, entities.time_range_hours,
        entities.query_intent,
    )

    # ------------------------------------------------------------------
    # Follow-up drift control
    # ------------------------------------------------------------------
    previous_session = None
    inherited = False

    if session_id:
        previous_session = session_manager.load(session_id)

    if entities.has_any_entities:
        if session_id:
            session_manager.reset_empty_followups(session_id)
    elif previous_session is not None:
        if session_manager.should_reset_entities(session_id):
            logger.info(
                "Drift threshold reached for session %s — clearing inherited entities",
                session_id,
            )
        else:
            prev = previous_session.entities
            entities.ips = prev.ips
            entities.hostnames = prev.hostnames
            entities.usernames = prev.usernames
            inherited = True
            session_manager.increment_empty_followups(session_id)
            logger.info(
                "Inherited entities from session %s (empty_followups=%d)",
                session_id,
                previous_session.consecutive_empty_followups + 1,
            )

    # Resolve effective time window (explicit in query → config default)
    log_hours = entities.time_range_hours or config.DEFAULT_LOG_TIME_RANGE_HOURS

    log_hits: list[dict] = []
    uba_hits: list[dict] = []
    insight_hits: list[dict] = []
    strategy = "none"

    search_terms = entities.ips + entities.hostnames + entities.usernames

    # When no entities are detected, extract key terms from the query so
    # keyword search on logs-* still runs.  This lets analysts ask generic
    # questions like "Show Fortigate login failures" without needing to
    # specify an IP, hostname, or user.
    if not search_terms:
        search_terms = _extract_query_terms(query)

    # ------------------------------------------------------------------
    # Intent-aware retrieval setup
    # ------------------------------------------------------------------
    intent = entities.query_intent
    skip_vector_search = (intent == "aggregate")

    # For aggregate intent, request TOP_K_LOGS * 4 (100 hits) for
    # enough data to answer ranking/counting questions.
    log_size = config.TOP_K_LOGS * 4 if intent == "aggregate" else config.TOP_K_LOGS

    # Only compute embedding when vector search will actually run
    query_vec: list[float] | None = None
    if not skip_vector_search:
        query_vec = embedding.encode(query)

    # ------------------------------------------------------------------
    # PARALLEL RETRIEVAL
    # ------------------------------------------------------------------
    # Submit all applicable searches concurrently.  Each future is
    # independent — failure in one source does not propagate to others.
    # Results are collected in deterministic order after all futures
    # resolve (or fail).
    # ------------------------------------------------------------------
    kw_future: Future | None = None
    vec_future: Future | None = None
    ins_future: Future | None = None
    uba_entity_future: Future | None = None

    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="retrieval") as pool:
        # Keyword search on logs-* (only when search terms exist)
        if search_terms:
            kw_future = pool.submit(
                _timed_keyword_search, search_terms, log_hours, log_size,
            )

        # Vector search on UBA — skip for aggregate intent
        if not skip_vector_search and query_vec is not None:
            vec_future = pool.submit(_timed_vector_search, query_vec)
            ins_future = pool.submit(_timed_insight_search, query_vec)

            # Entity-targeted UBA search — when entities exist
            if search_terms:
                uba_entity_future = pool.submit(
                    _timed_uba_entity_search, search_terms,
                )
        else:
            logger.info("Skipping vector search for %s intent", intent)

        # --- Collect results in fixed order (deterministic) ---------------
        if kw_future is not None:
            try:
                log_hits = kw_future.result()
                strategy = "keyword"
            except Exception:
                logger.exception("Keyword search failed")

        if vec_future is not None:
            try:
                uba_hits = vec_future.result()
                strategy = "hybrid" if strategy == "keyword" else "vector"
            except Exception:
                logger.exception("Vector search failed")

        # Merge entity-targeted UBA hits (dedup by user_id+summary)
        if uba_entity_future is not None:
            try:
                entity_uba_hits = uba_entity_future.result()
                seen = {(d.get("user_id"), d.get("summary")) for d in uba_hits}
                for doc in entity_uba_hits:
                    key = (doc.get("user_id"), doc.get("summary"))
                    if key not in seen:
                        uba_hits.append(doc)
                        seen.add(key)
            except Exception:
                logger.exception("UBA entity search failed")

        if ins_future is not None:
            try:
                insight_hits = ins_future.result()
            except Exception:
                pass

    # --- Fallback: broad keyword search bounded by time -------------------
    # Runs only when the parallel phase produced nothing.  This path is
    # NOT parallelised because it is mutually exclusive with the primary
    # keyword search — it fires only as a last resort.
    if not log_hits and not uba_hits:
        log_hits = _timed_keyword_search([query], log_hours, size=config.TOP_K_LOGS)
        strategy = "keyword_fallback"

    # --- Assemble risk-prioritised context --------------------------------
    context = _build_context(log_hits, uba_hits, insight_hits, intent=intent)

    if inherited:
        strategy = "session_followup"

    # --- Persist session (summarised context only, never raw data) ---------
    if session_id:
        session_manager.save(session_id, entities, context, strategy)

    elapsed_total = (_time.monotonic() - t0_total) * 1000
    logger.info("Total retrieval pipeline completed in %.1f ms", elapsed_total)

    return RetrievalResult(
        strategy=strategy,
        raw_hits=log_hits + uba_hits,
        context=context,
        entities=entities,
        session_id=session_id,
    )
