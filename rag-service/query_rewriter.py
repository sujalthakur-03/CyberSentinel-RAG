"""
Query rewriter — fixes spelling, grammar, and sentence structure using a
small T5 grammar-correction model before the query enters the RAG pipeline.

Loaded once at startup (lazy singleton). Adds ~100-300ms per query on CPU
for short analyst questions. Falls back to the original query on any error.
"""

import logging
import time as _time

from transformers import T5ForConditionalGeneration, AutoTokenizer

import config

logger = logging.getLogger(__name__)

_model: T5ForConditionalGeneration | None = None
_tokenizer: AutoTokenizer | None = None


def _load_model():
    """Load the T5 grammar correction model (lazy, once)."""
    global _model, _tokenizer
    if _model is not None:
        return

    model_name = config.QUERY_REWRITE_MODEL
    logger.info("Loading query rewrite model: %s", model_name)
    t0 = _time.monotonic()

    _tokenizer = AutoTokenizer.from_pretrained(model_name)
    _model = T5ForConditionalGeneration.from_pretrained(model_name)
    _model.eval()

    elapsed = (_time.monotonic() - t0) * 1000
    logger.info("Query rewrite model loaded in %.0f ms", elapsed)


def rewrite_query(raw_query: str) -> str:
    """
    Fix spelling and grammar in a user query.

    Returns the corrected query, or the original query unchanged if:
      - Query rewriting is disabled in config
      - The model fails to load or generate
      - The rewritten query is empty or suspiciously different

    Both original and rewritten queries are logged for audit.
    """
    if not config.QUERY_REWRITE_ENABLED:
        return raw_query

    try:
        _load_model()
    except Exception:
        logger.exception("Failed to load query rewrite model — using original query")
        return raw_query

    t0 = _time.monotonic()

    try:
        input_text = f"grammar: {raw_query}"
        input_ids = _tokenizer.encode(input_text, return_tensors="pt", max_length=128, truncation=True)

        outputs = _model.generate(
            input_ids,
            max_length=128,
            num_beams=2,
            early_stopping=True,
        )

        rewritten = _tokenizer.decode(outputs[0], skip_special_tokens=True).strip()
    except Exception:
        logger.exception("Query rewrite generation failed — using original query")
        return raw_query

    elapsed = (_time.monotonic() - t0) * 1000

    # Safety: if rewrite is empty or way too different in length, keep original
    if not rewritten:
        logger.warning("Query rewrite returned empty — using original (%.0f ms)", elapsed)
        return raw_query

    if rewritten.lower() == raw_query.lower():
        logger.info("Query unchanged after rewrite (%.0f ms)", elapsed)
        return raw_query

    logger.info(
        "Query rewritten (%.0f ms): %r → %r",
        elapsed, raw_query, rewritten,
    )
    return rewritten
