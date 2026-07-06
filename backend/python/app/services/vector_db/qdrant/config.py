from dataclasses import dataclass
from typing import Optional


@dataclass
class QdrantConfig:
    """Typed representation of the Qdrant connection config.

    NOTE: The live connection path (``QdrantService.connect_async`` /
    ``connect_sync`` in ``qdrant.py``) reads the raw config dict with
    camelCase keys (``apiKey``, ``grpcPort``, ``preferGrpc``, ``https``) as
    written by the Node.js seeder / the env fallback. This dataclass uses
    snake_case (``api_key``, ``prefer_grpc``) and is a parallel representation
    — keep the two key sets in sync if this is ever wired into ``connect()``.
    """

    host: str
    port: int
    api_key: str
    prefer_grpc: bool
    https: bool
    timeout: int
    # A full URL (e.g. a Qdrant Cloud endpoint) takes precedence over host/port/https.
    url: Optional[str] = None

    @property
    def qdrant_config(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "api_key": self.api_key,
            "prefer_grpc": self.prefer_grpc,
            "https": self.https,
            "timeout": self.timeout,
            "url": self.url,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'QdrantConfig':
        return cls(
            host=data.get("host", ""),
            port=data.get("port", 0),
            api_key=data.get("api_key", ""),
            prefer_grpc=data.get("prefer_grpc", True),
            https=data.get("https", False),
            timeout=data.get("timeout", 180),
            url=data.get("url"),
        )
