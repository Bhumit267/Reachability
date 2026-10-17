"""Database schema management, constraints, seed data loader, and graph inspection."""

import sys
from pathlib import Path
from typing import Dict, List, Optional
from falkordb import Graph
from redis.exceptions import ResponseError

# Allow direct script execution as well as module execution
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from src.db import get_graph

NODE_KEYS: Dict[str, str] = {
    "Service": "id",
    "CrownJewel": "id",
    "Asset": "id",
    "Vulnerability": "id",
    "Owner": "id",
    "OnCall": "id",
    "Repo": "id",
    "File": "id",
    "Function": "id",
    "Identity": "id",
    "Permission": "id",
    "Incident": "id",
    "Action": "id",
    "RunbookStep": "id",
    "MemoryEpisode": "id",
}


def create_constraints(graph: Optional[Graph] = None) -> None:
    """Create uniqueness constraints for all primary graph node keys."""
    g = graph or get_graph()
    for label, prop in NODE_KEYS.items():
        try:
            g.create_node_unique_constraint(label, prop)
        except ResponseError as exc:
            if "already exists" not in str(exc).lower():
                raise


def parse_cypher_file(file_path: Path) -> List[str]:
    """Parse a Cypher file into individual executable statements, removing comments."""
    raw_content = file_path.read_text(encoding="utf-8")
    statements: List[str] = []
    current_lines: List[str] = []

    for line in raw_content.splitlines():
        trimmed = line.strip()
        if not trimmed or trimmed.startswith("//"):
            continue
        current_lines.append(trimmed)
        if trimmed.endswith(";"):
            statement_str = " ".join(current_lines)[:-1].strip()
            if statement_str:
                statements.append(statement_str)
            current_lines = []

    return statements


def load_seed(seed_path: Optional[str] = None, graph: Optional[Graph] = None) -> int:
    """Idempotently execute Cypher statements from the seed data file."""
    g = graph or get_graph()
    path = Path(seed_path) if seed_path else Path(__file__).resolve().parent.parent / "data" / "seed.cypher"
    if not path.exists():
        raise FileNotFoundError(f"Seed file not found at: {path}")

    statements = parse_cypher_file(path)
    for statement in statements:
        g.query(statement)

    return len(statements)


def reset_graph(seed_path: Optional[str] = None, graph: Optional[Graph] = None) -> None:
    """Wipe the graph database completely, reapply constraints, and reload seed data."""
    g = graph or get_graph()
    try:
        g.delete()
    except ResponseError as exc:
        err = str(exc).lower()
        if "empty key" not in err and "not exist" not in err:
            raise

    create_constraints(g)
    load_seed(seed_path=seed_path, graph=g)


def summary(graph: Optional[Graph] = None) -> Dict[str, Dict[str, int]]:
    """Print and return node and edge counts per label and relationship type."""
    g = graph or get_graph()
    counts: Dict[str, Dict[str, int]] = {"nodes": {}, "edges": {}}

    print("=" * 48)
    print("         FALKORDB GRAPH SCHEMA SUMMARY          ")
    print("=" * 48)

    labels_res = g.query("CALL db.labels() YIELD label").result_set
    labels = sorted([row[0] for row in labels_res])
    print("\n--- NODE COUNTS BY LABEL ---")
    for label in labels:
        count_res = g.query(f"MATCH (n:{label}) RETURN count(n)").result_set
        node_count = count_res[0][0] if count_res else 0
        counts["nodes"][label] = node_count
        print(f"  {label:<16}: {node_count}")

    rel_res = g.query("CALL db.relationshipTypes() YIELD relationshipType").result_set
    rel_types = sorted([row[0] for row in rel_res])
    print("\n--- EDGE COUNTS BY TYPE ---")
    for rel_type in rel_types:
        count_res = g.query(f"MATCH ()-[r:{rel_type}]->() RETURN count(r)").result_set
        edge_count = count_res[0][0] if count_res else 0
        counts["edges"][rel_type] = edge_count
        print(f"  {rel_type:<16}: {edge_count}")

    total_nodes = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    total_edges = g.query("MATCH ()-[r]->() RETURN count(r)").result_set[0][0]
    print("\n--- TOTALS ---")
    print(f"  Total Nodes     : {total_nodes}")
    print(f"  Total Edges     : {total_edges}")
    print("=" * 48)

    return counts


if __name__ == "__main__":
    reset_graph()
    summary()
