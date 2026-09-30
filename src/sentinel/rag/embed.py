"""Local embeddings via sentence-transformers.

Measured on an M5 (bge-small-en-v1.5, 384-d, 512-token limit):
    cpu    545 chunks/sec
    mps  1,162 chunks/sec

The model is asymmetric: it was trained on (short query, long passage) pairs
with an instruction prefix on the query side only. Embedding a query the same
way as a passage measurably narrows the margin between the right answer and
the wrong one, so the two paths are separate functions rather than one
`encode()` everyone has to remember to call correctly.
"""

from __future__ import annotations

import functools

import numpy as np
import structlog

from sentinel.config import get_settings

log = structlog.get_logger()

# The instruction bge-* models were trained with. Passages get no prefix.
QUERY_INSTRUCTION = "Represent this sentence for searching relevant passages: "


def _pick_device() -> str:
    import torch

    if torch.backends.mps.is_available():
        return "mps"
    if torch.cuda.is_available():
        return "cuda"
    return "cpu"


@functools.lru_cache(maxsize=1)
def get_model():
    """Load once per process. The model is ~130MB and takes ~17s cold."""
    from sentence_transformers import SentenceTransformer

    settings = get_settings()
    device = _pick_device()
    model = SentenceTransformer(settings.embed_model, device=device)
    log.info("embed.model_loaded", model=settings.embed_model, device=device,
             dim=model.get_embedding_dimension())
    return model


def embed_passages(texts: list[str], batch_size: int | None = None) -> np.ndarray:
    """Embed corpus chunks. No instruction prefix -- passages are the
    'document' side of the asymmetric pair."""
    if not texts:
        return np.zeros((0, get_settings().embed_dim), dtype=np.float32)
    model = get_model()
    return model.encode(
        texts,
        batch_size=batch_size or get_settings().embed_batch_size,
        normalize_embeddings=True,   # required: we compare with cosine
        show_progress_bar=False,
        convert_to_numpy=True,
    ).astype(np.float32)


def embed_query(text: str) -> np.ndarray:
    """Embed a search query, with the instruction prefix the model expects."""
    model = get_model()
    return model.encode(
        [QUERY_INSTRUCTION + text],
        normalize_embeddings=True,
        show_progress_bar=False,
        convert_to_numpy=True,
    )[0].astype(np.float32)
