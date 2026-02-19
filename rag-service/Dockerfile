FROM python:3.12-slim

WORKDIR /app

# System deps for numpy / scipy (sentence-transformers transitive)
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

# Install CPU-only PyTorch FIRST.  sentence-transformers depends on torch,
# and without this explicit pin pip resolves the full CUDA build (~3 GB).
# The RAG service runs embeddings on CPU — the GPU lives on the remote
# Ollama server, not in this container.
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu

RUN pip install --no-cache-dir -r requirements.txt

# Pre-download models into the image so startup is fast
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
RUN python -c "from transformers import T5ForConditionalGeneration, AutoTokenizer; AutoTokenizer.from_pretrained('vennify/t5-base-grammar-correction'); T5ForConditionalGeneration.from_pretrained('vennify/t5-base-grammar-correction')"

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
