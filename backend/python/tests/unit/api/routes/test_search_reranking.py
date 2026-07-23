"""Focused tests for the enriched /search reranking path."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.routes.search import SearchQuery, search


@pytest.mark.asyncio
async def test_enriched_search_reranks_when_pool_is_not_larger_than_top_k():
    request = MagicMock()
    request.state.user = {"userId": "user-1", "orgId": "org-1"}
    request.app.container.logger.return_value = MagicMock()

    hits = [
        {"content": "first", "score": 0.1, "metadata": {}},
        {"content": "second", "score": 0.2, "metadata": {}},
    ]
    reranked_hits = [hits[1], hits[0]]

    retrieval_service = MagicMock()
    retrieval_service.search_with_filters = AsyncMock(
        return_value={
            "searchResults": hits,
            "status_code": 200,
            "virtual_to_record_map": {},
        }
    )
    reranker_service = MagicMock()
    reranker_service.rerank = AsyncMock(return_value=reranked_hits)

    flattened = [
        {
            "content": "second",
            "virtual_record_id": "record-1",
            "block_index": 0,
            "metadata": {},
        }
    ]

    with (
        patch(
            "app.api.routes.search.get_flattened_results",
            new=AsyncMock(return_value=flattened),
        ) as flatten_mock,
        patch(
            "app.api.routes.search.enrich_virtual_record_id_to_result_with_fk_children",
            new=AsyncMock(),
        ),
        patch(
            "app.api.routes.search.build_plain_context",
            return_value="context",
        ),
    ):
        response = await search(
            request=request,
            body=SearchQuery(query="needle", limit=10, top_k=10, enrich=True),
            retrieval_service=retrieval_service,
            graph_provider=MagicMock(),
            config_service=MagicMock(),
            reranker_service=reranker_service,
        )

    reranker_service.rerank.assert_awaited_once_with("needle", hits, top_k=10)
    assert flatten_mock.await_args.args[0] == reranked_hits
    payload = json.loads(response.body)
    assert payload["context"] == "context"
    assert payload["searchResults"] == flattened
