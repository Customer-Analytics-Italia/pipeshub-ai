import math
import re
import time
import unicodedata
from typing import TYPE_CHECKING, Any, Optional

from dependency_injector.wiring import inject
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.api.middlewares.auth import require_scopes
from app.config.configuration_service import ConfigurationService
from app.config.constants.service import OAuthScopes
from app.modules.retrieval.retrieval_service import RetrievalService
from app.modules.transformers.blob_storage import BlobStorage
from app.services.graph_db.interface.graph_db_provider import IGraphDBProvider
from app.utils.chat_helpers import (
    build_plain_context,
    enrich_virtual_record_id_to_result_with_fk_children,
    get_flattened_results,
)

if TYPE_CHECKING:
    from app.containers.query import QueryAppContainer

router = APIRouter()


# Pydantic models
class SearchQuery(BaseModel):
    query: str
    # Match the chat retrieval candidate pool.
    limit: int = Field(default=50, ge=1, le=100)
    filters: Optional[dict[str, Any]] = {}
    # Return chat-parity context by default so API consumers receive full block
    # content after hybrid retrieval. Callers can still opt out with enrich=false.
    enrich: bool = True
    # Optionally select the most relevant records and render their complete blob
    # content, matching the chat flow's fetch_full_record second pass.
    full_document: bool = True
    max_documents: int = Field(default=1, ge=1, le=5)


class SimilarDocumentQuery(BaseModel):
    document_id: str
    limit: Optional[int] = 5
    filters: Optional[dict[str, Any]] = None


class SearchRequest(BaseModel):
    query: str
    topK: int = 20
    filtersV1: list[dict[str, list[str]]]


async def get_retrieval_service(request: Request) -> RetrievalService:
    container: QueryAppContainer = request.app.container
    return await container.retrieval_service()


async def get_graph_provider(request: Request) -> IGraphDBProvider:
    container: QueryAppContainer = request.app.container
    return await container.graph_provider()


async def get_config_service(request: Request) -> ConfigurationService:
    container: QueryAppContainer = request.app.container
    return container.config_service()


_QUERY_STOP_WORDS = {
    "agli",
    "alla",
    "alle",
    "anche",
    "cosa",
    "come",
    "con",
    "dalla",
    "dalle",
    "della",
    "delle",
    "degli",
    "dei",
    "del",
    "gli",
    "nel",
    "nella",
    "nelle",
    "per",
    "serve",
    "sono",
    "una",
    "uno",
}


def _normalized_terms(text: str) -> list[str]:
    normalized = unicodedata.normalize("NFKD", text.casefold())
    normalized = "".join(char for char in normalized if not unicodedata.combining(char))
    return [
        token
        for token in re.findall(r"[a-z0-9]+", normalized)
        if len(token) >= 3 and token not in _QUERY_STOP_WORDS
    ]


def _content_to_plain_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "\n".join(
            text for item in value if (text := _content_to_plain_text(item))
        )
    if isinstance(value, dict):
        preferred_keys = (
            "row_natural_language_text",
            "text",
            "content",
            "value",
            "title",
            "label",
            "ddl",
            "table_summary",
        )
        preferred_parts = [
            text
            for key in preferred_keys
            if key in value and (text := _content_to_plain_text(value[key]))
        ]
        if preferred_parts:
            return "\n".join(preferred_parts)
        return "\n".join(
            text for item in value.values() if (text := _content_to_plain_text(item))
        )
    return ""


def _record_plain_text(record: dict[str, Any]) -> str:
    block_container = record.get("block_containers") or {}
    blocks = block_container.get("blocks") or []
    ordered_blocks = sorted(
        blocks,
        key=lambda block: block.get("index", 0) if isinstance(block, dict) else 0,
    )
    parts: list[str] = []
    seen: set[str] = set()
    for block in ordered_blocks:
        if not isinstance(block, dict) or block.get("type") == "image":
            continue
        text = _content_to_plain_text(block.get("data"))
        normalized = " ".join(_normalized_terms(text))
        if not text or normalized in seen:
            continue
        seen.add(normalized)
        parts.append(text)
    return "\n".join(parts)


def _hit_virtual_record_id(hit: dict[str, Any]) -> str | None:
    return hit.get("virtual_record_id") or (hit.get("metadata") or {}).get(
        "virtualRecordId"
    )


def _select_full_document_records(
    query: str,
    search_hits: list[dict[str, Any]],
    records: dict[str, dict[str, Any]],
    max_documents: int,
) -> list[dict[str, Any]]:
    candidate_ids = {
        vrid for hit in search_hits if (vrid := _hit_virtual_record_id(hit))
    }
    candidate_records = {
        vrid: record
        for vrid, record in records.items()
        if vrid in candidate_ids and isinstance(record, dict)
    }
    if not candidate_records:
        return []

    query_terms = list(dict.fromkeys(_normalized_terms(query)))
    record_texts = {
        vrid: _record_plain_text(record) for vrid, record in candidate_records.items()
    }
    record_term_sets = {
        vrid: set(
            _normalized_terms(
                " ".join(
                    [
                        record.get("record_name") or record.get("recordName") or "",
                        record_texts[vrid],
                    ]
                )
            )
        )
        for vrid, record in candidate_records.items()
    }

    document_count = len(candidate_records)
    document_frequency = {
        term: sum(term in terms for terms in record_term_sets.values())
        for term in query_terms
    }
    idf = {
        term: math.log((document_count + 1) / (document_frequency[term] + 1)) + 1
        for term in query_terms
    }
    total_query_weight = sum(idf.values()) or 1.0

    retrieval_scores: dict[str, float] = {}
    for hit in search_hits:
        vrid = _hit_virtual_record_id(hit)
        if vrid not in candidate_records:
            continue
        retrieval_scores[vrid] = max(
            retrieval_scores.get(vrid, 0.0), float(hit.get("score") or 0.0)
        )
    max_retrieval_score = max(retrieval_scores.values(), default=1.0) or 1.0

    ranked: list[dict[str, Any]] = []
    for vrid, record in candidate_records.items():
        terms = record_term_sets[vrid]
        title_terms = set(
            _normalized_terms(
                record.get("record_name") or record.get("recordName") or ""
            )
        )
        lexical_coverage = (
            sum(idf[term] for term in query_terms if term in terms) / total_query_weight
        )
        rare_coverage = (
            sum(
                idf[term]
                for term in query_terms
                if term in terms
                and document_frequency[term] <= max(1, document_count // 2)
            )
            / total_query_weight
        )
        title_coverage = (
            sum(idf[term] for term in query_terms if term in title_terms)
            / total_query_weight
        )
        retrieval_score = retrieval_scores.get(vrid, 0.0) / max_retrieval_score
        combined_score = (
            lexical_coverage * 3.0
            + rare_coverage * 2.0
            + title_coverage
            + retrieval_score * 0.25
        )
        ranked.append(
            {
                "virtualRecordId": vrid,
                "recordId": record.get("id") or record.get("recordId"),
                "recordName": record.get("record_name")
                or record.get("recordName")
                or "Untitled",
                "score": round(combined_score, 6),
                "_record": record,
                "_text": record_texts[vrid],
            }
        )

    ranked.sort(key=lambda item: item["score"], reverse=True)
    return ranked[:max_documents]


def _build_full_document_context(selected_records: list[dict[str, Any]]) -> str:
    sections = []
    for selected in selected_records:
        text = selected["_text"].strip()
        if text:
            sections.append(f"## {selected['recordName']}\n{text}")
    return "\n\n".join(sections)


@router.post(
    "/search", dependencies=[Depends(require_scopes(OAuthScopes.SEMANTIC_WRITE))]
)
@inject
async def search(
    request: Request,
    body: SearchQuery,
    retrieval_service: RetrievalService = Depends(get_retrieval_service),
    graph_provider: IGraphDBProvider = Depends(get_graph_provider),
    config_service: ConfigurationService = Depends(get_config_service),
) -> JSONResponse:
    """Perform semantic search across documents"""
    try:
        container = request.app.container
        logger = container.logger()
        # Extract KB IDs from filters if present
        updated_filters = body.filters
        org_id = request.state.user.get("orgId")
        user_id = request.state.user.get("userId")

        # --- LLM query rewrite + expansion (DISABLED) ---
        # To re-enable: uncomment the block below, pass `queries=queries` to
        # search_with_filters, and re-add the imports at the top of this file:
        #   import asyncio
        #   from app.utils.query_transform import setup_query_transformation
        # llm = retrieval_service.llm
        # if llm is None:
        #     llm = await retrieval_service.get_llm_instance()
        #     if llm is None:
        #         raise HTTPException(
        #             status_code=500,
        #             detail="Failed to initialize LLM service. LLM configuration is missing.",
        #         )
        # rewrite_chain, expansion_chain = setup_query_transformation(llm)
        # rewritten_query, expanded_queries = await asyncio.gather(
        #     rewrite_chain.ainvoke(body.query), expansion_chain.ainvoke(body.query)
        # )
        # expanded_queries_list = [
        #     q.strip() for q in expanded_queries.split("\n") if q.strip()
        # ]
        # queries = [rewritten_query.strip()] if rewritten_query.strip() else []
        # queries.extend([q for q in expanded_queries_list if q not in queries])
        # --- end LLM query rewrite + expansion ---

        retrieval_started = time.perf_counter()
        results = await retrieval_service.search_with_filters(
            queries=[body.query],
            org_id=org_id,
            user_id=user_id,
            limit=body.limit,
            filter_groups=updated_filters,
        )
        retrieval_ms = (time.perf_counter() - retrieval_started) * 1000
        custom_status_code = results.get("status_code", 500)
        logger.info(f"Custom status code: {custom_status_code}")
        enrichment_ms = 0.0
        candidate_count = len(results.get("searchResults") or [])

        # Chat-parity enrichment applies the same post-retrieval steps the chat
        # flow runs (get_flattened_results + FK-child blocks + document order)
        # so a caller with its own LLM receives the context chat feeds its LLM.
        if body.enrich and custom_status_code == 200 and results.get("searchResults"):
            # Match the chat path: preserve Qdrant's hybrid dense+BM25/RRF
            # ordering, then flatten and enrich the complete candidate pool.
            search_hits = results["searchResults"]

            enrichment_started = time.perf_counter()
            blob_store = BlobStorage(
                logger=logger,
                config_service=config_service,
                graph_provider=graph_provider,
            )
            virtual_record_id_to_result: dict[str, Any] = {}
            flattened_results = await get_flattened_results(
                search_hits,
                blob_store,
                org_id,
                False,  # is_multimodal_llm — text-only context for the external LLM
                virtual_record_id_to_result,
                results.get("virtual_to_record_map", {}),
                graph_provider=graph_provider,
            )
            await enrich_virtual_record_id_to_result_with_fk_children(
                virtual_record_id_to_result,
                blob_store,
                org_id,
                graph_provider,
                flattened_results,
            )
            if body.full_document:
                selected_records = _select_full_document_records(
                    body.query,
                    search_hits,
                    virtual_record_id_to_result,
                    body.max_documents,
                )
                selected_ids = {
                    selected["virtualRecordId"] for selected in selected_records
                }
                selected_order = {
                    selected["virtualRecordId"]: index
                    for index, selected in enumerate(selected_records)
                }
                filtered_results = [
                    result
                    for result in flattened_results
                    if result.get("virtual_record_id") in selected_ids
                ]
                filtered_results.sort(
                    key=lambda result: (
                        selected_order.get(
                            result.get("virtual_record_id"), body.max_documents
                        ),
                        result.get("block_index", 0),
                    )
                )
                full_context = _build_full_document_context(selected_records)
                if full_context:
                    results["searchResults"] = filtered_results
                    results["context"] = full_context
                    results["selectedRecords"] = [
                        {
                            key: value
                            for key, value in selected.items()
                            if not key.startswith("_")
                        }
                        for selected in selected_records
                    ]
                else:
                    flattened_results.sort(
                        key=lambda result: (
                            result.get("virtual_record_id", ""),
                            result.get("block_index", 0),
                        )
                    )
                    results["searchResults"] = flattened_results
                    results["context"] = build_plain_context(
                        flattened_results, virtual_record_id_to_result
                    )
            else:
                flattened_results.sort(
                    key=lambda result: (
                        result.get("virtual_record_id", ""),
                        result.get("block_index", 0),
                    )
                )
                results["searchResults"] = flattened_results
                # Clean plain-text context (no prompt scaffolding, no citation refs)
                # for a caller running its own LLM — same content the chat LLM sees.
                results["context"] = build_plain_context(
                    flattened_results, virtual_record_id_to_result
                )
            enrichment_ms = (time.perf_counter() - enrichment_started) * 1000

        logger.info(
            "Search timings: retrieval=%.1fms enrichment=%.1fms "
            "candidates=%d returned=%d enrich=%s full_document=%s selected=%d",
            retrieval_ms,
            enrichment_ms,
            candidate_count,
            len(results.get("searchResults") or []),
            body.enrich,
            body.full_document,
            len(results.get("selectedRecords") or []),
        )

        return JSONResponse(status_code=custom_status_code, content=results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint"""
    return {"status": "healthy"}
