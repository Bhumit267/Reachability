"""Tests for FalkorDB database connection and health check."""

from src.db import ping, get_graph


def test_falkordb_ping() -> None:
    """Verify that FalkorDB responds successfully to a health check ping."""
    assert ping() is True


def test_falkordb_get_graph() -> None:
    """Verify that get_graph returns a valid Graph client instance."""
    graph = get_graph()
    assert graph is not None
