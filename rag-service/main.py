"""
CyberSentinel RAG Service — FastAPI application (v2).

Endpoints:
    POST /query          — answer a cybersecurity question via RAG
    GET  /health         — liveness / readiness probe
    POST /index/uba      — (utility) index a UBA behaviour summary document
"""

import hashlib
import logging
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

import config
import embedding
import llm_client
import opensearch_client
import retriever

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Lifespan (startup / shutdown)
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CyberSentinel RAG service")
    # Eagerly load the embedding model so the first request isn't slow
    embedding.encode("warmup")
    # Ensure required indices exist
    try:
        opensearch_client.ensure_uba_index()
        opensearch_client.ensure_insights_index()
    except Exception:
        logger.warning("Could not reach OpenSearch at startup — will retry on first request")
    yield
    logger.info("Shutting down CyberSentinel RAG service")


app = FastAPI(
    title="CyberSentinel RAG Service",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------
class QueryRequest(BaseModel):
    question: str = Field(..., min_length=3, examples=[
        "Show recent activity for IP 10.0.1.42",
        "Are there any anomalous login patterns for user:jdoe?",
    ])
    # Optional session ID for follow-up questions.  If omitted on the first
    # query the service generates one and returns it in the response.  The
    # caller should send it back on subsequent questions in the same
    # investigation thread so the retriever can inherit entities.
    session_id: Optional[str] = Field(
        default=None,
        examples=["550e8400-e29b-41d4-a716-446655440000"],
    )


class QueryResponse(BaseModel):
    answer: str
    strategy: str
    sources_count: int
    context_preview: str
    session_id: str              # always returned — caller stores this for follow-ups
    time_range_used_hours: int   # effective lookback applied to log search


class UBADocRequest(BaseModel):
    user_id: str
    hostname: str = ""
    summary: str
    risk_score: float = 0.0
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
def health():
    """Basic health check."""
    return {"status": "ok", "model": config.EMBEDDING_MODEL_NAME}


@app.post("/query", response_model=QueryResponse)
def query(req: QueryRequest):
    """
    Full RAG pipeline:
      1. Resolve or create a session ID.
      2. Detect entities + time range in the question.
      3. Retrieve from OpenSearch (keyword / vector / hybrid) with time filters.
      4. Aggregate and summarise retrieved docs into structured context.
      5. Send summarised context + question to Ollama Vicuna-13B.
      6. Return the answer with session ID for follow-up support.
    """
    # Resolve session — generate a new one if caller didn't provide one
    session_id = req.session_id or str(uuid.uuid4())

    # Step 1–4: retrieval with time filtering, aggregation, session awareness
    result = retriever.retrieve(req.question, session_id=session_id)

    # Effective time range used (for transparency in the response)
    effective_hours = (
        result.entities.time_range_hours
        or config.DEFAULT_LOG_TIME_RANGE_HOURS
    )

    # Guard: if no primary data was retrieved (logs + UBA), return early
    # without calling the LLM.  Past insights alone are NOT sufficient
    # context — sending only insights leads to hallucination because the
    # LLM fabricates data that "fits" the insight narrative.
    if not result.raw_hits:
        return QueryResponse(
            answer="No relevant data found in OpenSearch for your query.",
            strategy=result.strategy,
            sources_count=0,
            context_preview="",
            session_id=session_id,
            time_range_used_hours=effective_hours,
        )

    # Step 5: LLM generation
    try:
        answer = llm_client.generate(
            context=result.context,
            question=req.question,
        )
    except Exception as exc:
        logger.exception("LLM generation failed")
        raise HTTPException(
            status_code=502,
            detail=f"LLM backend error: {exc}",
        )

    # Step 6: Persist insight for future retrieval (fire-and-forget).
    # Only the question, a hash of the summarised context, the LLM answer,
    # and detected entities are stored — never raw logs or full context.
    # SKIP storage when the LLM refused to answer — persisting refusal
    # phrases like "Insufficient data" poisons future insight retrieval
    # and makes the LLM repeat wrong refusals even when data is available.
    _REFUSAL_PHRASES = (
        "insufficient data",
        "no relevant data",
        "not enough information",
        "cannot determine",
        "impossible to determine",
        "no information available",
    )
    answer_lower = answer.lower()
    should_store = not any(phrase in answer_lower for phrase in _REFUSAL_PHRASES)

    if should_store:
        try:
            context_hash = hashlib.sha256(result.context.encode()).hexdigest()
            query_vec = embedding.encode(req.question)
            opensearch_client.store_insight(
                question=req.question,
                answer=answer,
                context_hash=context_hash,
                entities_ip=result.entities.ips,
                entities_hostname=result.entities.hostnames,
                entities_username=result.entities.usernames,
                query_vector=query_vec,
            )
        except Exception:
            # Insight storage is non-critical — log and move on
            logger.debug("Failed to store insight (non-critical)", exc_info=True)
    else:
        logger.info("Skipping insight storage — answer contains refusal phrase")

    return QueryResponse(
        answer=answer,
        strategy=result.strategy,
        sources_count=len(result.raw_hits),
        context_preview=result.context[:500],
        session_id=session_id,
        time_range_used_hours=effective_hours,
    )


@app.post("/index/uba", status_code=201)
def index_uba_document(doc: UBADocRequest):
    """
    Utility endpoint to ingest a UBA behaviour summary into OpenSearch
    with its embedding pre-computed.
    """
    vec = embedding.encode(doc.summary)
    body = {
        "user_id": doc.user_id,
        "hostname": doc.hostname,
        "summary": doc.summary,
        "risk_score": doc.risk_score,
        "tags": doc.tags,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "embedding": vec,
    }
    client = opensearch_client.get_client()
    resp = client.index(index=config.UBA_INDEX, body=body)
    return {"result": resp.get("result"), "id": resp.get("_id")}
