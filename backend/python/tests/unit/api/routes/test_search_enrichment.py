"""Focused tests for the chat-parity /search enrichment path."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.routes.search import SearchQuery, search


@pytest.mark.asyncio
async def test_enriched_search_preserves_retrieval_pool_for_flattening():
    request = MagicMock()
    request.state.user = {"userId": "user-1", "orgId": "org-1"}
    request.app.container.logger.return_value = MagicMock()

    hits = [
        {"content": "first", "score": 0.2, "metadata": {}},
        {"content": "second", "score": 0.1, "metadata": {}},
    ]
    retrieval_service = MagicMock()
    retrieval_service.search_with_filters = AsyncMock(
        return_value={
            "searchResults": hits,
            "status_code": 200,
            "virtual_to_record_map": {},
        }
    )
    flattened = [
        {
            "content": "first",
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
            body=SearchQuery(query="needle", limit=50, enrich=True),
            retrieval_service=retrieval_service,
            graph_provider=MagicMock(),
            config_service=MagicMock(),
        )

    assert flatten_mock.await_args.args[0] == hits
    retrieval_kwargs = retrieval_service.search_with_filters.await_args.kwargs
    assert retrieval_kwargs["limit"] == 50
    assert "knowledge_search" not in retrieval_kwargs
    payload = json.loads(response.body)
    assert payload["context"] == "context"
    assert payload["searchResults"] == flattened
