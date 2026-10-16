"""ensure_payload_indexes: the keyword indexes the pipeline filters on, on every collection."""
import logging
from unittest.mock import AsyncMock

import pytest

from app.services.vector_db import payload_indexes
from app.services.vector_db.payload_indexes import PAYLOAD_INDEX_FIELDS, ensure_payload_indexes


@pytest.fixture(autouse=True)
def fresh_process():
    payload_indexes._ensured.clear()
    yield
    payload_indexes._ensured.clear()


@pytest.mark.asyncio
async def test_creates_the_block_id_index_with_the_others_once_per_collection():
    service = AsyncMock()

    await ensure_payload_indexes(service, "records", logging.getLogger("t"))
    await ensure_payload_indexes(service, "records", logging.getLogger("t"))

    fields = [c.kwargs["field_name"] for c in service.create_index.await_args_list]
    assert fields == list(PAYLOAD_INDEX_FIELDS)
    assert "metadata.blockId" in fields


@pytest.mark.asyncio
async def test_a_failed_index_does_not_stop_the_others_and_is_retried():
    service = AsyncMock()
    service.create_index.side_effect = [RuntimeError("busy"), None, None, None, None, None]

    await ensure_payload_indexes(service, "records", logging.getLogger("t"))
    assert service.create_index.await_count == len(PAYLOAD_INDEX_FIELDS)

    await ensure_payload_indexes(service, "records", logging.getLogger("t"))
    assert service.create_index.await_count == 2 * len(PAYLOAD_INDEX_FIELDS)
