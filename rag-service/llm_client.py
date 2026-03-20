"""
Ollama HTTP client for Qwen3-14B — production v3.

Changes from v2:
  - Switched from /api/generate to /api/chat for proper role-based messaging.
  - Qwen3 non-thinking mode via "think" option — disables internal CoT for
    faster, direct answers (ideal for RAG where context is pre-assembled).
  - Persistent httpx client with connection pooling.
  - Strips any residual <think> blocks from output as a safety net.
"""

import logging
import re

import httpx

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Persistent HTTP client — reused across all LLM calls in this worker.
# Avoids per-request TCP handshake overhead and enables HTTP keepalive.
# ---------------------------------------------------------------------------
_http_client = httpx.Client(
    timeout=config.OLLAMA_TIMEOUT,
    limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
)

# Regex to strip any residual <think>...</think> blocks from Qwen3 output.
_THINK_BLOCK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)

# ---------------------------------------------------------------------------
# System instruction — the LLM's operating mandate
# ---------------------------------------------------------------------------
_SYSTEM_INSTRUCTION = (
    "You are CyberSentinel AI, created by the CyberSentinel Developer Team.\n"
    "If the user asks who you are, your name, or your identity, respond with:\n"
    "\"I am CyberSentinel AI, created by the CyberSentinel Developer Team. "
    "Feel free to ask any question about the SIEM logs.\"\n"
    "\n"
    "You are a cybersecurity analyst assistant for the CyberSentinel platform.\n"
    "\n"
    "RULES — you must follow these without exception:\n"
    "1. Answer ONLY using the CONTEXT provided in the user message.\n"
    "2. The CONTEXT contains structured log summaries with detail fields like\n"
    "   policy_ids, actions, src_ips, dst_ips, services, apps, rule_ids,\n"
    "   mitre_techniques, users, ports, interfaces, etc. READ ALL of these\n"
    "   fields carefully — the answer is often in the detail fields.\n"
    "3. The CONTEXT is a representative sample retrieved from the requested\n"
    "   time window — it may not cover every minute of the period. Treat the\n"
    "   data present as the best available evidence and answer based on it.\n"
    "4. Only say \"Insufficient data available to determine the answer.\" if\n"
    "   the context contains NO relevant information at all for the question.\n"
    "5. Do NOT invent, assume, or fabricate any data, log entries, IP addresses,\n"
    "   hostnames, timestamps, or user identities.\n"
    "6. When referencing data, cite the source block (e.g. IP/Host, User) so the\n"
    "   analyst can verify.\n"
    "7. Be concise.  SOC analysts need actionable answers, not essays.\n"
    "8. When High-Risk Behavioral Alerts are present in the context, PRIORITIZE\n"
    "   them in your analysis.  Flag the risk score and explain why the behavior\n"
    "   is noteworthy before covering lower-risk details.\n"
    "9. Do NOT generalize beyond what the provided context explicitly states.\n"
    "   If the context shows 5 failed logins, say '5 failed logins' — do not\n"
    "   say 'many failed logins' or 'a large number of attempts'.\n"
    "10. TERMINOLOGY MAPPING — these terms refer to the same concepts:\n"
    "   - File Integrity Monitoring / FIM = syscheck, file-creation, file modified/added/deleted\n"
    "   - Brute Force = authentication_failed, Login failed, T1110\n"
    "   - Lateral Movement = T1021, RDP, remote session\n"
    "   - VPN = SSL VPN, ssl-login-fail, xauthuser\n"
    "   - Firewall = Fortigate, block, deny, pass, policy\n"
    "   When the question uses one term, match it against ALL equivalent terms in the context.\n"
    "11. When the CONTEXT contains an 'Aggregation Results' section with explicit\n"
    "   counts and rankings, use those EXACT numbers. These counts are computed\n"
    "   across ALL matching documents, not a sample. Present them as definitive.\n"
)


def _build_user_message(context: str, question: str) -> str:
    """
    Assemble the user message with context + question.

    Context is hard-capped here as a last line of defence even if the
    retriever already truncated it, because prompt injection payloads
    inside documents could attempt to bloat the context window.
    """
    safe_context = context[: config.MAX_CONTEXT_CHARS]

    return (
        f"/no_think\n"
        f"CONTEXT:\n{safe_context}\n\n"
        f"QUESTION:\n{question}"
    )


def generate(context: str, question: str) -> str:
    """
    Call Ollama's /api/chat endpoint (non-streaming) and return
    the model's response text.

    Uses Qwen3 non-thinking mode for faster direct answers.

    Raises httpx.HTTPStatusError or httpx.ConnectError on failure.
    """
    user_message = _build_user_message(context, question)
    url = f"{config.OLLAMA_BASE_URL}/api/chat"

    payload = {
        "model": config.OLLAMA_MODEL,
        "messages": [
            {"role": "system", "content": _SYSTEM_INSTRUCTION},
            {"role": "user", "content": user_message},
        ],
        "stream": False,
        "options": {
            "num_ctx": 20480,
            "temperature": 0.3,
            "top_p": 0.9,
            "num_predict": 2048,
        },
    }

    logger.info(
        "Sending prompt to Ollama (%s) — user message: %d chars, "
        "context portion: %d chars",
        config.OLLAMA_MODEL,
        len(user_message),
        len(context),
    )

    try:
        resp = _http_client.post(url, json=payload)
        resp.raise_for_status()
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Ollama HTTP error: %s — %s",
            exc.response.status_code,
            exc.response.text[:500],
        )
        raise
    except httpx.ConnectError:
        logger.error("Cannot reach Ollama at %s", url)
        raise

    data = resp.json()
    raw_content = data.get("message", {}).get("content", "")
    done_reason = data.get("done_reason", "unknown")
    answer = raw_content.strip()

    # Safety net: strip any residual <think> blocks if model emits them
    has_think = "<think>" in raw_content
    answer = _THINK_BLOCK_RE.sub("", answer).strip()

    logger.info(
        "Ollama response (%d raw chars, %d final, think=%s, done_reason=%s)",
        len(raw_content), len(answer), has_think, done_reason,
    )

    # Retry once if the model returned empty (Qwen3 occasionally does this
    # on first attempt with large contexts)
    if not answer:
        logger.warning("Empty response from LLM — retrying once")
        resp = _http_client.post(url, json=payload)
        resp.raise_for_status()
        data = resp.json()
        raw_content = data.get("message", {}).get("content", "")
        answer = _THINK_BLOCK_RE.sub("", raw_content).strip()
        logger.info("Retry response (%d chars)", len(answer))
    return answer
