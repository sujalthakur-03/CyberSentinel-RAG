"""
Lightweight entity extraction from user queries.

Detects IP addresses, hostnames, usernames, and explicit time ranges so the
retriever can decide which search strategy to use and how far back to look.
"""

import re
from dataclasses import dataclass, field
from typing import Optional

# RFC-1918 & public IPv4
_IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Hostnames: FQDN (at least one dot, TLD 2-10 chars)
_FQDN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,10}\b"
)

# Internal hostnames: hyphenated multi-part names (2+ segments).
# Matches: workstation-89, dc-primary-01, soc-Virtual-Machine,
# fileserver-03, hr-server-02, db-prod-01.
# Requires 3+ total chars per segment to avoid matching short
# English hyphenations like "re-run" or "co-op".
_INTERNAL_HOST_RE = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9]{2,}(?:-[a-zA-Z0-9]{2,})+\b"
)

# System identifiers: tokens containing underscores (VGIL_DC, soc_server),
# or ALL-CAPS words of 3+ chars that aren't common English words.
# These are treated as hostnames/device names for search purposes.
_SYSTEM_ID_RE = re.compile(
    r"\b[a-zA-Z][a-zA-Z0-9]*(?:_[a-zA-Z0-9]+)+\b"       # underscore-separated: VGIL_DC
)
_ALLCAPS_RE = re.compile(
    r"\b[A-Z][A-Z0-9]{2,}\b"                              # ALL_CAPS 3+ chars: FGT, SIEM
)
# Common English uppercase words to exclude from identifier detection
_ALLCAPS_STOPWORDS = frozenset({
    "THE", "AND", "FOR", "ARE", "BUT", "NOT", "YOU", "ALL",
    "CAN", "HER", "WAS", "ONE", "OUR", "OUT", "HAS", "DNS",
    "SSH", "VPN", "RDP", "TCP", "UDP", "HTTP", "API", "SSL",
    "TLS", "GET", "POST", "PUT",
})

# Usernames: explicit "user:<value>" or "username:<value>" patterns
_USER_RE = re.compile(
    r"\b(?:user(?:name)?)\s*[:=]\s*([A-Za-z0-9._\\@\-]+)", re.IGNORECASE
)

# Behavioural / analytical signal words
_BEHAVIORAL_KEYWORDS = {
    "anomaly", "anomalies", "anomalous",
    "behavior", "behaviour", "behavioral",
    "pattern", "patterns",
    "unusual", "suspicious",
    "risk", "risky",
    "baseline", "deviation",
    "trend", "trends",
    "summary", "profile",
    "lateral", "exfiltration", "exfiltrate", "brute",
    "escalat", "privilege",
    "c2", "command and control", "beacon",
    "tunnel", "tunneling", "dns",
    "malware", "ransomware", "phishing",
    "unauthorized", "compromise", "compromised",
    "attack", "threat", "exploit",
    "intrusion", "breach",
    "credential", "login", "logon",
    "rdp", "powershell",
}

# ---------------------------------------------------------------------------
# Time-range expressions
# ---------------------------------------------------------------------------
# Maps natural language time phrases to lookback hours.
# Order matters: longer patterns first to prevent partial matches.
_TIME_EXPRESSIONS: list[tuple[re.Pattern, int]] = [
    (re.compile(r"\b(?:last|past)\s+(\d+)\s+days?\b", re.I),   None),  # dynamic — N*24
    (re.compile(r"\b(?:last|past)\s+(\d+)\s+hours?\b", re.I),   None),  # dynamic — N
    (re.compile(r"\b(?:last|past)\s+(\d+)\s+minutes?\b", re.I), None),  # dynamic — ceil(N/60)
    (re.compile(r"\b(?:last|past)\s+month\b", re.I),             720),   # 30 days
    (re.compile(r"\b(?:last|past)\s+week\b", re.I),              168),   # 7 days
    (re.compile(r"\b(?:last|past)\s+7\s+days?\b", re.I),         168),
    (re.compile(r"\b(?:last|past)\s+30\s+days?\b", re.I),        720),
    (re.compile(r"\b(?:last|past)\s+24\s+hours?\b", re.I),       24),
    (re.compile(r"\btoday\b", re.I),                              24),
    (re.compile(r"\byesterday\b", re.I),                          48),
    (re.compile(r"\bthis\s+week\b", re.I),                        168),
]


@dataclass
class DetectedEntities:
    ips: list[str] = field(default_factory=list)
    hostnames: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    is_behavioral: bool = False
    # Explicit lookback hours parsed from query text, or None to use default.
    time_range_hours: Optional[int] = None
    # Query intent: "aggregate", "behavioral", "entity_investigation", "general"
    query_intent: str = "general"

    @property
    def has_network_entities(self) -> bool:
        return bool(self.ips or self.hostnames)

    @property
    def has_user_entities(self) -> bool:
        return bool(self.usernames)

    @property
    def has_any_entities(self) -> bool:
        return self.has_network_entities or self.has_user_entities


# ---------------------------------------------------------------------------
# Query intent classification
# ---------------------------------------------------------------------------
_AGGREGATE_PATTERNS = [
    re.compile(r"\bwhich\s+\w+\s+has\s+the\s+most\b", re.I),
    re.compile(r"\bhow\s+many\b", re.I),
    re.compile(r"\bcount\s+of\b", re.I),
    re.compile(r"\btop\s+\d+\b", re.I),
    re.compile(r"\bshow\s+all\b", re.I),
    re.compile(r"\blist\s+all\b", re.I),
    re.compile(r"\bmost\s+\w+\b", re.I),
    re.compile(r"\btotal\s+number\b", re.I),
    re.compile(r"\brank\b", re.I),
    re.compile(r"\bgrouped?\s+by\b", re.I),
    re.compile(r"\bbreakdown\b", re.I),
    re.compile(r"\bper\s+(agent|host|user|ip|source)\b", re.I),
]


def _classify_intent(query: str, entities: DetectedEntities) -> str:
    """
    Classify the query into one of four intent categories:
      - aggregate: counting, ranking, or listing questions
      - behavioral: UBA/anomaly-focused questions
      - entity_investigation: specific entity lookups
      - general: fallback
    """
    query_lower = query.lower()

    # Check aggregate patterns first — these should get raw log data
    for pat in _AGGREGATE_PATTERNS:
        if pat.search(query_lower):
            return "aggregate"

    # Behavioral intent — reuse the existing flag
    if entities.is_behavioral:
        return "behavioral"

    # Entity investigation — has specific entities but not aggregate/behavioral
    if entities.has_any_entities:
        return "entity_investigation"

    return "general"


def _parse_time_range(query: str) -> Optional[int]:
    """
    Scan query for explicit time expressions and return lookback hours.
    Returns None when no time expression is found (caller uses default).
    """
    import math

    for pattern, static_hours in _TIME_EXPRESSIONS:
        m = pattern.search(query)
        if m:
            if static_hours is not None:
                return static_hours
            # Dynamic patterns: the regex captured a numeric group
            n = int(m.group(1))
            if "day" in pattern.pattern:
                return n * 24
            if "hour" in pattern.pattern:
                return n
            if "minute" in pattern.pattern:
                return max(1, math.ceil(n / 60))
    return None


def detect_entities(query: str) -> DetectedEntities:
    """Parse a natural-language query and return structured entities."""
    entities = DetectedEntities()

    entities.ips = _IP_RE.findall(query)
    # Merge FQDN, internal hostname, and system identifier matches
    fqdn_matches = _FQDN_RE.findall(query)
    internal_matches = _INTERNAL_HOST_RE.findall(query)
    system_id_matches = _SYSTEM_ID_RE.findall(query)
    allcaps_matches = [
        w for w in _ALLCAPS_RE.findall(query)
        if w not in _ALLCAPS_STOPWORDS
    ]
    entities.hostnames = list(dict.fromkeys(
        fqdn_matches + internal_matches + system_id_matches + allcaps_matches
    ))

    user_matches = _USER_RE.findall(query)
    entities.usernames = list(dict.fromkeys(user_matches))  # dedupe, keep order

    query_lower = query.lower()
    entities.is_behavioral = any(kw in query_lower for kw in _BEHAVIORAL_KEYWORDS)

    # Time-range: explicit mention overrides the default window
    entities.time_range_hours = _parse_time_range(query)

    # Classify query intent for downstream retrieval routing
    entities.query_intent = _classify_intent(query, entities)

    return entities
