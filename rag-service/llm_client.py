"""
Ollama HTTP client for the Vicuna-13B model — production v2.

Changes from v1:
  - Strict system instruction that forces the LLM to stay within context.
  - Explicit SYSTEM / CONTEXT / QUESTION block structure.
  - Hard cap on context length before prompt assembly (defence in depth).
  - Clear refusal phrase when context is insufficient.
"""

import logging

import httpx

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# System instruction — the LLM's operating mandate
# ---------------------------------------------------------------------------
# This is intentionally stern.  Vicuna-13B is instruction-tuned but will
# hallucinate freely when given vague guardrails.  The phrasing below was
# chosen to minimise fabrication in cybersecurity Q&A where accuracy matters.
_SYSTEM_INSTRUCTION = (
    "You are a cybersecurity analyst assistant for the CyberSentinel platform.\n"
    "\n"
    "RULES — you must follow these without exception:\n"
    "1. Answer ONLY using the CONTEXT block provided below.\n"
    "2. The CONTEXT contains structured log summaries with detail fields like\n"
    "   policy_ids, actions, src_ips, dst_ips, services, apps, rule_ids,\n"
    "   mitre_techniques, users, ports, interfaces, etc. READ ALL of these\n"
    "   fields carefully — the answer is often in the detail fields.\n"
    "3. If the context is insufficient to answer the question, respond EXACTLY with:\n"
    '   "Insufficient data available to determine the answer."\n'
    "4. Do NOT invent, assume, or fabricate any data, log entries, IP addresses,\n"
    "   hostnames, timestamps, or user identities.\n"
    "5. When referencing data, cite the source block (e.g. IP/Host, User) so the\n"
    "   analyst can verify.\n"
    "6. Be concise.  SOC analysts need actionable answers, not essays.\n"
    "7. When High-Risk Behavioral Alerts are present in the context, PRIORITIZE\n"
    "   them in your analysis.  Flag the risk score and explain why the behavior\n"
    "   is noteworthy before covering lower-risk details.\n"
    "8. Do NOT generalize beyond what the provided context explicitly states.\n"
    "   If the context shows 5 failed logins, say '5 failed logins' — do not\n"
    "   say 'many failed logins' or 'a large number of attempts'.\n"
)


def _build_prompt(context: str, question: str) -> str:
    """
    Assemble the final prompt with strict block structure:
        SYSTEM MESSAGE  →  sets behavioral constraints
        CONTEXT BLOCK   →  retrieved + aggregated data (never raw logs)
        USER QUESTION   →  the analyst's natural-language query

    Context is hard-capped here as a last line of defence even if the
    retriever already truncated it, because prompt injection payloads
    inside documents could attempt to bloat the context window.
    """
    # Defence-in-depth context cap
    safe_context = context[: config.MAX_CONTEXT_CHARS]

    return (
        f"### SYSTEM\n{_SYSTEM_INSTRUCTION}\n"
        f"### CONTEXT\n{safe_context}\n\n"
        f"### QUESTION\n{question}\n\n"
        f"### ANSWER\n"
    )


def generate(context: str, question: str) -> str:
    """
    Call Ollama's /api/generate endpoint (non-streaming) and return
    the model's response text.

    Raises httpx.HTTPStatusError or httpx.ConnectError on failure.
    """
    prompt = _build_prompt(context, question)
    url = f"{config.OLLAMA_BASE_URL}/api/generate"

    payload = {
        "model": config.OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.3,
            "top_p": 0.9,
            "num_predict": 1024,
        },
    }

    logger.info(
        "Sending prompt to Ollama (%s) — prompt length: %d chars, "
        "context portion: %d chars",
        config.OLLAMA_MODEL,
        len(prompt),
        len(context),
    )

    try:
        with httpx.Client(timeout=config.OLLAMA_TIMEOUT) as client:
            resp = client.post(url, json=payload)
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
    answer = data.get("response", "").strip()
    logger.info("Ollama response received (%d chars)", len(answer))
    return answer
