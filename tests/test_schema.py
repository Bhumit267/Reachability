"""Tests for schema initialization, seed loading, and graph topology."""

from src.db import get_graph
from src.schema import reset_graph, summary, load_seed, NODE_KEYS


def test_schema_reset_and_summary() -> None:
    """Verify reset_graph populates all target labels and summary returns non-zero counts."""
    reset_graph()
    counts = summary()

    for label in NODE_KEYS.keys():
        assert label in counts["nodes"], f"Missing label {label} in nodes summary"
        assert counts["nodes"][label] > 0, f"Label {label} has 0 nodes"

    assert counts["nodes"]["Service"] == 10
    assert counts["nodes"]["CrownJewel"] == 5
    assert counts["nodes"]["Asset"] == 15
    assert counts["nodes"]["Owner"] == 5
    assert counts["nodes"]["OnCall"] == 5
    assert counts["nodes"]["Repo"] == 5
    assert counts["nodes"]["Identity"] == 3
    assert counts["nodes"]["Incident"] == 3


def test_seed_idempotency() -> None:
    """Verify executing load_seed multiple times does not duplicate nodes."""
    g = get_graph()
    initial_count = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    load_seed()
    second_count = g.query("MATCH (n) RETURN count(n)").result_set[0][0]
    assert initial_count == second_count


def test_payments_api_attack_path() -> None:
    """Verify that a traversable attack path exists from payments-api asset to a CrownJewel."""
    g = get_graph()
    query = """
    MATCH (s:Service {name: 'payments-api'})-[:RUNS_ON]->(a:Asset)-[:USES_IDENTITY]->(i:Identity)-[:HAS_PERMISSION]->(p:Permission)-[:GRANTS_ACCESS_TO]->(cj:CrownJewel)
    RETURN s.name, a.id, i.name, p.name, cj.name
    """
    res = g.query(query).result_set
    assert len(res) > 0
    assert res[0][0] == "payments-api"


def test_payments_api_critical_cve() -> None:
    """Verify that an asset running payments-api is affected by a CRITICAL CVE."""
    g = get_graph()
    query = """
    MATCH (s:Service {name: 'payments-api'})-[:RUNS_ON]->(a:Asset)-[:HAS_VULN]->(v:Vulnerability {severity: 'CRITICAL'})
    RETURN v.cve_id, v.cvss
    """
    res = g.query(query).result_set
    assert len(res) > 0
    assert res[0][0] == "CVE-2024-3094"
    assert res[0][1] == 10.0


def test_payments_api_code_mapping() -> None:
    """Verify payments-api repo maps to payment_handler.py with function process_payment."""
    g = get_graph()
    query = """
    MATCH (s:Service {name: 'payments-api'})-[:HAS_REPO]->(r:Repo)-[:CONTAINS]->(f:File {path: 'src/payment_handler.py'})-[:DEFINES]->(fn:Function {name: 'process_payment'})
    RETURN s.name, r.name, f.path, fn.name
    """
    res = g.query(query).result_set
    assert len(res) == 1
    assert res[0][3] == "process_payment"


def test_past_incident_with_failed_runbook_step() -> None:
    """Verify that a past incident on payments-api contains a FAILED runbook step."""
    g = get_graph()
    query = """
    MATCH (inc:Incident)-[:AFFECTS]->(s:Service {name: 'payments-api'}),
          (inc)-[:FOLLOWS]->(rb:RunbookStep {status: 'FAILED'})
    RETURN inc.id, rb.name, rb.failure_reason
    """
    res = g.query(query).result_set
    assert len(res) >= 1
    assert "WAF" in res[0][2]
