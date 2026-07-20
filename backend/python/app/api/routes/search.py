from typing import TYPE_CHECKING, Any, Optional

from dependency_injector.wiring import inject
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from app.api.middlewares.auth import require_scopes
from app.config.configuration_service import ConfigurationService
from app.config.constants.service import OAuthScopes
from app.modules.reranker.reranker import RerankerService
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
    limit: Optional[int] = 5
    filters: Optional[dict[str, Any]] = {}
    # Opt-in: return chat-parity enriched context (full block content + FK-child
    # blocks + document order) instead of raw matched chunks. Off by default so
    # existing /search consumers are unaffected.
    enrich: Optional[bool] = False
    # On the enrich path, `limit` is the candidate pool and `top_k` is how many
    # chunks survive reranking and reach the context. Only used when enrich=true.
    top_k: Optional[int] = 10


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


async def get_reranker_service(request: Request) -> RerankerService:
    container: QueryAppContainer = request.app.container
    return container.reranker_service()


@router.post("/search", dependencies=[Depends(require_scopes(OAuthScopes.SEMANTIC_WRITE))])
@inject
async def search(
    request: Request,
    body: SearchQuery,
    retrieval_service: RetrievalService = Depends(get_retrieval_service),
    graph_provider: IGraphDBProvider = Depends(get_graph_provider),
    config_service: ConfigurationService = Depends(get_config_service),
    reranker_service: RerankerService = Depends(get_reranker_service),
)-> JSONResponse :
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

        results = await retrieval_service.search_with_filters(
            queries=[body.query],
            org_id=org_id,
            user_id=user_id,
            limit=body.limit,
            filter_groups=updated_filters,
            knowledge_search=True,
        )
        custom_status_code = results.get("status_code", 500)
        logger.info(f"Custom status code: {custom_status_code}")

        # Opt-in chat-parity enrichment: apply the same post-retrieval steps the
        # chat flow runs (get_flattened_results + FK-child blocks + document order)
        # so a caller with its own LLM receives the context chat feeds its LLM.
        if body.enrich and custom_status_code == 200 and results.get("searchResults"):
            # Retrieve wide (limit = candidate pool), rerank with the multilingual
            # cross-encoder, and keep only top_k — so a low-ranked-but-relevant
            # chunk surfaces without enriching the whole pool. Skipped when the pool
            # is already <= top_k.
            search_hits = results["searchResults"]
            top_k = body.top_k or 10
            if len(search_hits) > top_k:
                search_hits = await reranker_service.rerank(
                    body.query, search_hits, top_k=top_k
                )

            blob_store = BlobStorage(
                logger=logger, config_service=config_service, graph_provider=graph_provider
            )
            virtual_record_id_to_result: dict[str, Any] = {}
            flattened_results = await get_flattened_results(
                search_hits,
                blob_store,
                org_id,
                False,  # is_multimodal_llm — text-only context for the external LLM
                virtual_record_id_to_result,
                results.get("virtual_to_record_map", {}),
                from_retrieval_service=True,
                graph_provider=graph_provider,
            )
            await enrich_virtual_record_id_to_result_with_fk_children(
                virtual_record_id_to_result, blob_store, org_id, graph_provider, flattened_results
            )
            flattened_results.sort(
                key=lambda x: (x.get("virtual_record_id", ""), x.get("block_index", 0))
            )
            results["searchResults"] = flattened_results
            # Clean plain-text context (no prompt scaffolding, no citation refs)
            # for a caller running its own LLM — same content the chat LLM sees.
            results["context"] = build_plain_context(
                flattened_results, virtual_record_id_to_result
            )

        return JSONResponse(status_code=custom_status_code, content=results)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) from e


@router.get("/health")
async def health_check() -> dict[str, str]:
    """Health check endpoint"""
    return {"status": "healthy"}
