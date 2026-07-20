import asyncio
from typing import Any, Dict, List, Optional

from app.models.blocks import BlockType, GroupType

# Multilingual (incl. Italian), Apache-2.0, small encoder — loaded as ONNX for
# CPU inference. The `onnx-community` export ships a plain ONNX graph so we avoid
# `trust_remote_code`. See openspec/changes/add-search-reranking.
DEFAULT_RERANKER_MODEL = "onnx-community/gte-multilingual-reranker-base"
_MAX_LENGTH = 512
_BATCH_SIZE = 16


class RerankerService:
    """Reranks retrieval results with a multilingual cross-encoder (ONNX, CPU)."""

    def __init__(self, model_name: str = DEFAULT_RERANKER_MODEL) -> None:
        """
        Args:
            model_name: an ONNX cross-encoder reranker on HuggingFace. Default is
                gte-multilingual-reranker-base (Apache-2.0, multilingual), loaded
                via optimum.onnxruntime for CPU inference.

        Note:
            The model is NOT loaded here. Loading (and, on a cold cache,
            downloading) blocks and would stall the asyncio event loop. We defer
            the load to the first `rerank()` call, run it in `asyncio.to_thread`,
            and serialize it with an `asyncio.Lock` so concurrent first callers
            share a single load. In production the model is baked into the image
            (see Dockerfile), so the first load is fast.
        """
        self.model_name = model_name
        self._model = None
        self._tokenizer = None
        self._model_lock = asyncio.Lock()

    def _load_model_sync(self):
        """Blocking load of the ONNX reranker + tokenizer. Runs in a worker thread."""
        from optimum.onnxruntime import ORTModelForSequenceClassification
        from transformers import AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        # onnx-community exports keep the graph under an `onnx/` subfolder.
        model = ORTModelForSequenceClassification.from_pretrained(
            self.model_name, subfolder="onnx"
        )
        return model, tokenizer

    async def _ensure_model_loaded(self):
        """Lazily load the reranker on first use, off the event loop."""
        if self._model is not None:
            return self._model, self._tokenizer
        async with self._model_lock:
            if self._model is None:
                self._model, self._tokenizer = await asyncio.to_thread(self._load_model_sync)
        return self._model, self._tokenizer

    def _predict_scores_sync(self, model, tokenizer, pairs: List[tuple]) -> List[float]:
        """Score (query, passage) pairs with the ONNX cross-encoder. CPU-bound."""
        scores: List[float] = []
        for start in range(0, len(pairs), _BATCH_SIZE):
            batch = pairs[start:start + _BATCH_SIZE]
            inputs = tokenizer(
                [p[0] for p in batch],
                [p[1] for p in batch],
                padding=True,
                truncation=True,
                max_length=_MAX_LENGTH,
                return_tensors="pt",
            )
            logits = model(**inputs).logits.reshape(-1)
            scores.extend(logits.tolist())
        return scores

    async def rerank(
        self, query: str, documents: List[Dict[str, Any]], top_k: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Rerank documents by relevance to the query.

        Args:
            query: the search query
            documents: retriever result dicts (each with a string ``content``)
            top_k: number of top documents to return (None for all)

        Returns:
            Reranked documents (top_k) with ``reranker_score`` / ``final_score``.
            On any failure, returns the input order (sliced to top_k) so search
            degrades gracefully rather than erroring.
        """
        if not documents:
            return []

        # Create document-query pairs for scoring
        doc_query_pairs = []
        for doc in documents:
            content = doc.get("content", "")
            if content:
                block_type = doc.get("block_type")
                if block_type == GroupType.TABLE.value:
                    doc_query_pairs.append((query, content[0]))
                elif block_type != BlockType.IMAGE.value:
                    doc_query_pairs.append((query, content))

        # If no valid pairs, return documents as-is (sliced)
        if not doc_query_pairs:
            for doc in documents:
                doc["reranker_score"] = 0.0
                doc["final_score"] = doc.get("score", 0.0)
            return documents[:top_k] if top_k is not None else documents

        try:
            model, tokenizer = await self._ensure_model_loaded()
            # Tokenization + ONNX inference are CPU-bound and synchronous; run in a
            # worker thread so we never stall the event loop (the first call also
            # triggers the lazy load above).
            scores = await asyncio.to_thread(
                self._predict_scores_sync, model, tokenizer, doc_query_pairs
            )
        except Exception:
            for doc in documents:
                doc["reranker_score"] = 0.0
                doc["final_score"] = doc.get("score", 0.0)
            return documents[:top_k] if top_k is not None else documents

        # Add scores to documents, but only for non-IMAGE blocks with content
        score_index = 0
        for doc in documents:
            if doc.get("block_type") != BlockType.IMAGE.value and doc.get("content"):
                doc["reranker_score"] = float(scores[score_index])
                if "score" in doc:
                    # Weighted combination of retriever and reranker scores
                    doc["final_score"] = 0.3 * doc["score"] + 0.7 * doc["reranker_score"]
                else:
                    doc["final_score"] = doc["reranker_score"]
                score_index += 1
            else:
                doc["reranker_score"] = 0.0
                doc["final_score"] = doc.get("score", 0.0)

        reranked_docs = sorted(
            documents, key=lambda d: d.get("final_score", 0), reverse=True
        )

        if top_k is not None:
            return reranked_docs[:top_k]
        return reranked_docs
