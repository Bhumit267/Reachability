"""Database connection management and health checks for FalkorDB."""

from typing import Optional
from falkordb import FalkorDB, Graph

from src.config import Settings, get_settings


def get_client(settings: Optional[Settings] = None) -> FalkorDB:
    """Create and return a connected FalkorDB client instance."""
    cfg = settings or get_settings()
    return FalkorDB(host=cfg.falkordb_host, port=cfg.falkordb_port)


def get_graph(graph_name: Optional[str] = None, settings: Optional[Settings] = None) -> Graph:
    """Return a FalkorDB Graph client selected for FALKORDB_GRAPH."""
    cfg = settings or get_settings()
    client = get_client(cfg)
    target_graph = graph_name or cfg.falkordb_graph
    return client.select_graph(target_graph)


def ping(settings: Optional[Settings] = None) -> bool:
    """Check connectivity to FalkorDB and return True if healthy."""
    cfg = settings or get_settings()
    client = get_client(cfg)
    return bool(client.connection.ping())
