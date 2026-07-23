"""Focused tests for the chat-parity /search enrichment path."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.api.routes.search import SearchQuery, search


@pytest.mark.asyncio
async def test_enriched_search_preserves_retrieval_pool_for_flattening() -> None:
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


@pytest.mark.asyncio
async def test_full_document_selects_specific_record_and_renders_all_blocks() -> None:
    request = MagicMock()
    request.state.user = {"userId": "user-1", "orgId": "org-1"}
    request.app.container.logger.return_value = MagicMock()

    hits = [
        {
            "content": "Accesso con Carta d'Identità Elettronica",
            "score": 0.9,
            "metadata": {"virtualRecordId": "generic-record"},
        },
        {
            "content": "Carta d'identità elettronica (CIE)",
            "score": 0.8,
            "metadata": {"virtualRecordId": "cie-record"},
        },
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
            "content": "Accesso con CIE",
            "virtual_record_id": "generic-record",
            "block_index": 0,
            "metadata": {},
        },
        {
            "content": "Cosa serve",
            "virtual_record_id": "cie-record",
            "block_index": 0,
            "metadata": {},
        },
    ]
    records = {
        "generic-record": {
            "id": "generic-id",
            "record_name": "bonus-economico",
            "block_containers": {
                "blocks": [
                    {
                        "index": 0,
                        "type": "text",
                        "data": "Accesso tramite SPID o Carta d'Identità Elettronica",
                    }
                ]
            },
        },
        "cie-record": {
            "id": "cie-id",
            "record_name": "carta-didentita-elettronica-cie",
            "block_containers": {
                "blocks": [
                    {
                        "index": 0,
                        "type": "text",
                        "data": "Per la CIE serve una fototessera recente.",
                    },
                    {
                        "index": 1,
                        "type": "text",
                        "data": "Gli occhiali sono ammessi se gli occhi restano visibili.",
                    },
                ]
            },
        },
    }

    async def flatten_with_records(
        _hits,
        _blob_store,
        _org_id,
        _is_multimodal,
        virtual_record_id_to_result,
        *_args,
        **_kwargs,
    ) -> list[dict]:
        virtual_record_id_to_result.update(records)
        return flattened

    with (
        patch(
            "app.api.routes.search.get_flattened_results",
            new=AsyncMock(side_effect=flatten_with_records),
        ),
        patch(
            "app.api.routes.search.enrich_virtual_record_id_to_result_with_fk_children",
            new=AsyncMock(),
        ),
    ):
        response = await search(
            request=request,
            body=SearchQuery(
                query="Carta d'identità elettronica fototessera occhiali cosa serve",
                limit=50,
                enrich=True,
                full_document=True,
                max_documents=1,
            ),
            retrieval_service=retrieval_service,
            graph_provider=MagicMock(),
            config_service=MagicMock(),
        )

    payload = json.loads(response.body)
    assert payload["selectedRecords"][0]["virtualRecordId"] == "cie-record"
    assert payload["selectedRecords"][0]["recordName"] == (
        "carta-didentita-elettronica-cie"
    )
    assert "fototessera recente" in payload["context"]
    assert "occhiali sono ammessi" in payload["context"]
    assert "bonus-economico" not in payload["context"]
    assert {result["virtual_record_id"] for result in payload["searchResults"]} == {
        "cie-record"
    }
