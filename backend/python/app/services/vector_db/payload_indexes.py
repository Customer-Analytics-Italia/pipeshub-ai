"""Payload indexes the indexing pipeline filters on.

Qdrant refuses a filtered delete on an unindexed payload field ("Index required
but not found"). Updating a record deletes its changed blocks by
``metadata.blockId``, so every collection needs that index too, including
collections created before it was added: they are ensured on start, not only
when a collection is created.
"""
import logging

from app.services.vector_db.const.const import (
    BLOCK_ID_FIELD,
    ORG_ID_FIELD,
    VIRTUAL_RECORD_ID_FIELD,
)

PAYLOAD_INDEX_FIELDS = (VIRTUAL_RECORD_ID_FIELD, ORG_ID_FIELD, BLOCK_ID_FIELD)

# Collections whose indexes this process already ensured.
_ensured: set[str] = set()


async def ensure_payload_indexes(vector_db_service, collection_name: str, logger: logging.Logger) -> None:
    """Create the keyword indexes the pipeline needs; existing ones are left as they are."""
    if collection_name in _ensured:
        return
    complete = True
    for field_name in PAYLOAD_INDEX_FIELDS:
        try:
            await vector_db_service.create_index(
                collection_name=collection_name,
                field_name=field_name,
                field_schema={"type": "keyword"},
            )
        except Exception as e:
            complete = False
            logger.warning(f"⚠️ Could not ensure payload index {field_name} on {collection_name}: {e}")
    if complete:
        _ensured.add(collection_name)
