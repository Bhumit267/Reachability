"""All named Cypher queries encapsulated as typed functions returning Pydantic models."""

import uuid
from typing import List, Optional
from falkordb import Graph

from src.db import get_graph
from src.models import (
    AttackPath,
    CodeImpact,
    CveAssessment,
    GraphPath,
    IncidentTimeline,
    MemoryEpisodeModel,
    OwnerOnCall,
    ServiceModel,
    TimelineEvent,
)


def _format_path_readable(nodes: List[str], edges: List[str]) -> str:
    """Format nodes and edges into an ASCII representation of the traversal path."""
    if not nodes:
        return ""
    result = [nodes[0]]
    for i in range(len(edges)):
        next_node = nodes[i + 1] if i + 1 < len(nodes) else "?"
        result.append(f"-[:{edges[i]}]-> {next_node}")
    return " ".join(result)


def get_service(name: str, graph: Optional[Graph] = None) -> Optional[ServiceModel]:
    """Retrieve metadata for a service by canonical name or identifier."""
    if not name or not name.strip():
        return None
    g = graph or get_graph()
    cypher = "MATCH (s:Service) WHERE s.name = $name OR s.id = $name RETURN s.id, s.name, s.tier, s.critical, s.language LIMIT 1"
    res = g.query(cypher, {"name": name.strip()}).result_set
    if not res:
        return None
    r = res[0]
    return ServiceModel(id=r[0], name=r[1], tier=r[2], critical=bool(r[3]), language=r[4])


def find_attack_paths(service_name: str, graph: Optional[Graph] = None) -> List[AttackPath]:
    """Find shortest traversable attack paths from a service's assets to crown jewels."""
    if not service_name or not service_name.strip():
        return []
    g = graph or get_graph()
    cypher = (
        "MATCH path = (s:Service)-[:RUNS_ON]->(a:Asset)-[:REACHES]->(cj:CrownJewel) "
        "WHERE s.name = $svc OR s.id = $svc "
        "RETURN [n IN nodes(path) | coalesce(n.name, n.id)], [r IN relationships(path) | type(r)], cj.name, length(path) "
        "UNION "
        "MATCH path = (s:Service)-[:RUNS_ON]->(a:Asset)-[:USES_IDENTITY]->(i:Identity)-[:HAS_PERMISSION]->(p:Permission)-[:GRANTS_ACCESS_TO]->(cj:CrownJewel) "
        "WHERE s.name = $svc OR s.id = $svc "
        "RETURN [n IN nodes(path) | coalesce(n.name, n.id)], [r IN relationships(path) | type(r)], cj.name, length(path)"
    )
    res = g.query(cypher, {"svc": service_name.strip()}).result_set
    paths, seen = [], set()
    for row in res:
        names, rels, cj, hops = row[0], row[1], row[2], int(row[3])
        sig = "->".join(names)
        if sig in seen:
            continue
        seen.add(sig)
        readable = _format_path_readable(names, rels)
        risk = round(max(1.0, 10.0 - (hops - 2) * 1.5), 1)
        paths.append(AttackPath(path=GraphPath(nodes=names, edges=rels, readable=readable), crown_jewel=cj, hops=hops, risk_score=risk))
    return sorted(paths, key=lambda ap: ap.risk_score, reverse=True)


def rank_cves_by_reachability(service_name: str, graph: Optional[Graph] = None) -> List[CveAssessment]:
    """Rank vulnerabilities on a service's assets based on CVSS severity and crown jewel reachability."""
    if not service_name or not service_name.strip():
        return []
    g = graph or get_graph()
    cypher = (
        "MATCH (s:Service)-[:RUNS_ON]->(a:Asset)-[:HAS_VULN]->(v:Vulnerability) WHERE s.name = $svc OR s.id = $svc "
        "OPTIONAL MATCH (a)-[:REACHES|USES_IDENTITY*1..4]->(cj:CrownJewel) "
        "RETURN v.cve_id, v.severity, v.cvss, collect(DISTINCT a.name), collect(DISTINCT cj.name) ORDER BY v.cvss DESC"
    )
    res = g.query(cypher, {"svc": service_name.strip()}).result_set
    assessments = []
    for r in res:
        cve, sev, cvss, assets, cjs = r[0], r[1], float(r[2]), [str(x) for x in r[3] if x], [str(x) for x in r[4] if x]
        reason = (
            f"CVSS {cvss} ({sev}) on {', '.join(assets)} directly reaches {len(cjs)} crown jewel(s): {', '.join(cjs)}."
            if cjs else f"CVSS {cvss} ({sev}) on {', '.join(assets)} without direct crown jewel path."
        )
        assessments.append(CveAssessment(cve=cve, severity=sev, affected_assets=assets, reachable_crown_jewels=cjs, rank_reason=reason))
    return assessments


def get_affected_assets(service_name: str, graph: Optional[Graph] = None) -> List[str]:
    """Return all host and database asset names hosting the specified service."""
    if not service_name or not service_name.strip():
        return []
    g = graph or get_graph()
    cypher = "MATCH (s:Service)-[:RUNS_ON]->(a:Asset) WHERE s.name = $svc OR s.id = $svc RETURN DISTINCT a.name ORDER BY a.name"
    return [str(row[0]) for row in g.query(cypher, {"svc": service_name.strip()}).result_set]


def get_code_impact(service_name: str, graph: Optional[Graph] = None) -> Optional[CodeImpact]:
    """Map a service to its repository, exposed files, functions, owner, and on-call rotation."""
    if not service_name or not service_name.strip():
        return None
    g = graph or get_graph()
    cypher = (
        "MATCH (s:Service)-[:HAS_REPO]->(r:Repo) WHERE s.name = $svc OR s.id = $svc "
        "OPTIONAL MATCH (r)-[:CONTAINS]->(f:File) OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function) "
        "OPTIONAL MATCH (s)-[:OWNED_BY]->(o:Owner) OPTIONAL MATCH (o)-[:ON_CALL]->(oc:OnCall) "
        "RETURN s.name, r.name, collect(DISTINCT f.path), collect(DISTINCT fn.name), coalesce(o.name, 'Unassigned'), coalesce(oc.name, 'Unassigned') LIMIT 1"
    )
    res = g.query(cypher, {"svc": service_name.strip()}).result_set
    if not res:
        return None
    r = res[0]
    svc, repo, files, functions = str(r[0]), str(r[1]), [str(f) for f in r[2] if f], [str(fn) for fn in r[3] if fn]
    owner, on_call = str(r[4]), str(r[5])
    primary_file, primary_fn = files[0] if files else "unknown_file", functions[0] if functions else "unknown_fn"
    path = GraphPath(
        nodes=[svc, repo, primary_file, primary_fn, owner, on_call],
        edges=["HAS_REPO", "CONTAINS", "DEFINES", "OWNED_BY", "ON_CALL"],
        readable=f"{svc} -[:HAS_REPO]-> {repo} -[:CONTAINS]-> {primary_file} -[:DEFINES]-> {primary_fn} -[:OWNED_BY]-> {owner} -[:ON_CALL]-> {on_call}",
    )
    return CodeImpact(service=svc, repo=repo, files=files, functions=functions, owner=owner, on_call=on_call, path=path)


def get_owners_and_oncall(service_name: str, graph: Optional[Graph] = None) -> Optional[OwnerOnCall]:
    """Retrieve owner details and primary on-call contact for the specified service."""
    if not service_name or not service_name.strip():
        return None
    g = graph or get_graph()
    cypher = (
        "MATCH (s:Service)-[:OWNED_BY]->(o:Owner) WHERE s.name = $svc OR s.id = $svc "
        "OPTIONAL MATCH (o)-[:ON_CALL]->(oc:OnCall) "
        "RETURN s.name, o.name, o.email, o.team, coalesce(oc.name, 'Unassigned'), coalesce(oc.phone, ''), coalesce(oc.schedule, ''), coalesce(oc.active, false) LIMIT 1"
    )
    res = g.query(cypher, {"svc": service_name.strip()}).result_set
    if not res:
        return None
    r = res[0]
    return OwnerOnCall(
        service=str(r[0]), owner_name=str(r[1]), owner_email=str(r[2]), team=str(r[3]),
        oncall_name=str(r[4]), oncall_phone=str(r[5]), oncall_schedule=str(r[6]), active=bool(r[7])
    )


def find_similar_incidents(
    service_name: str, limit: int = 3, graph: Optional[Graph] = None
) -> List[MemoryEpisodeModel]:
    """Retrieve historical incident memory episodes and past lessons learned for a service."""
    if not service_name or not service_name.strip():
        return []
    g = graph or get_graph()
    cypher = (
        "MATCH (m:MemoryEpisode) WHERE m.service = $svc OR m.service = ('svc-' + $svc) "
        "OPTIONAL MATCH (inc:Incident {id: m.incident_id}) OPTIONAL MATCH (inc)-[:FOLLOWS]->(rb:RunbookStep) "
        "RETURN m.id, m.summary, m.service, coalesce(m.outcome, m.key_takeaway, m.lesson_learned, 'Resolved'), "
        "coalesce(m.runbook_step, rb.name, 'Default Runbook Mitigation'), coalesce(m.success, rb.status = 'SUCCESS', true), "
        "coalesce(m.timestamp, inc.created_at, '2024-01-01T00:00:00Z') ORDER BY m.timestamp DESC LIMIT $limit"
    )
    res = g.query(cypher, {"svc": service_name.strip(), "limit": limit}).result_set
    episodes, seen = [], set()
    for r in res:
        ep_id, step = str(r[0]), str(r[4])
        key = f"{ep_id}-{step}"
        if key in seen:
            continue
        seen.add(key)
        episodes.append(MemoryEpisodeModel(id=ep_id, summary=str(r[1]), service=str(r[2]), outcome=str(r[3]), runbook_step=step, success=bool(r[5]), timestamp=str(r[6])))
    return episodes


def write_memory_episode(episode: MemoryEpisodeModel, graph: Optional[Graph] = None) -> MemoryEpisodeModel:
    """Store or update a memory episode node and associate it with relevant incidents."""
    g = graph or get_graph()
    cypher = (
        "MERGE (m:MemoryEpisode {id: $id}) "
        "SET m.summary = $summary, m.service = $service, m.outcome = $outcome, "
        "m.runbook_step = $runbook_step, m.success = $success, m.timestamp = $timestamp "
        "RETURN m.id, m.summary, m.service, m.outcome, m.runbook_step, m.success, m.timestamp"
    )
    res = g.query(cypher, episode.model_dump()).result_set[0]
    return MemoryEpisodeModel(id=str(res[0]), summary=str(res[1]), service=str(res[2]), outcome=str(res[3]), runbook_step=str(res[4]), success=bool(res[5]), timestamp=str(res[6]))


def get_incident_timeline(incident_id: str, graph: Optional[Graph] = None) -> Optional[IncidentTimeline]:
    """Construct a chronological timeline of actions and runbook executions for an incident."""
    if not incident_id or not incident_id.strip():
        return None
    g = graph or get_graph()
    cypher = (
        "MATCH (inc:Incident) WHERE inc.id = $inc_id "
        "OPTIONAL MATCH (inc)-[:AFFECTS]->(s:Service) OPTIONAL MATCH (inc)-[:HAS_ACTION]->(act:Action) "
        "OPTIONAL MATCH (inc)-[:FOLLOWS]->(rb:RunbookStep) "
        "RETURN inc.id, coalesce(inc.title, inc.id), coalesce(s.name, 'Unknown'), "
        "collect(DISTINCT {id: act.id, type: act.type, target: act.target, status: act.status, executed_at: act.executed_at}), "
        "collect(DISTINCT {id: rb.id, name: rb.name, step_number: rb.step_number, status: rb.status, failure_reason: rb.failure_reason}) LIMIT 1"
    )
    res = g.query(cypher, {"inc_id": incident_id.strip()}).result_set
    if not res:
        return None
    r = res[0]
    events: List[TimelineEvent] = []
    for act in (r[3] or []):
        if isinstance(act, dict) and act.get("id"):
            events.append(
                TimelineEvent(
                    event_type="ACTION", name=str(act.get("type", "ACTION")), status=str(act.get("status", "UNKNOWN")),
                    timestamp=str(act.get("executed_at") or "2024-08-21T14:35:00Z"), details=f"Target: {act.get('target', 'N/A')}",
                )
            )
    for step in (r[4] or []):
        if isinstance(step, dict) and step.get("id"):
            details = f"Step #{step.get('step_number', 0)}" + (f" | Reason: {step.get('failure_reason')}" if step.get("failure_reason") else "")
            events.append(
                TimelineEvent(event_type="RUNBOOK_STEP", name=str(step.get("name", "Step")), status=str(step.get("status", "UNKNOWN")), timestamp="2024-08-21T14:36:00Z", details=details)
            )
    events.sort(key=lambda e: e.timestamp)
    return IncidentTimeline(incident_id=str(r[0]), title=str(r[1]), service=str(r[2]), events=events)


def link_memory_episode(
    episode_id: str, service_name: str, incident_id: Optional[str] = None, graph: Optional[Graph] = None
) -> None:
    """Link a memory episode to its incident and similar past incidents affecting the same service."""
    g = graph or get_graph()
    if incident_id:
        cypher_inc = "MATCH (inc:Incident), (m:MemoryEpisode {id: $ep}) WHERE inc.id = $inc MERGE (inc)-[:REMEMBERS]->(m)"
        g.query(cypher_inc, {"inc": incident_id, "ep": episode_id})
    cypher_sim = (
        "MATCH (m:MemoryEpisode {id: $ep}), (past_inc:Incident) "
        "WHERE past_inc.service_id = $svc OR past_inc.service_id = ('svc-' + $svc) "
        "MERGE (m)-[:SIMILAR_TO]->(past_inc)"
    )
    g.query(cypher_sim, {"ep": episode_id, "svc": service_name})


def record_incident_action(
    incident_id: str, action_type: str, target: str, status: str, log_line: str, graph: Optional[Graph] = None
) -> str:
    """Persist an Action node and attach it to an Incident node in FalkorDB."""
    g, act_id = graph or get_graph(), f"act-{uuid.uuid4().hex[:8]}"
    cypher = (
        "MERGE (a:Action {id: $aid}) SET a.type = $type, a.target = $target, a.status = $status, a.log = $log "
        "WITH a MATCH (i:Incident) WHERE i.id = $iid OR i.id = ('inc-' + $iid) MERGE (i)-[:HAS_ACTION]->(a)"
    )
    g.query(cypher, {"aid": act_id, "type": action_type, "target": target, "status": status, "log": log_line, "iid": incident_id})
    return act_id


def attach_incident_action(incident_id: str, action_id: str, graph: Optional[Graph] = None) -> None:
    """Attach an Action node to an Incident node via HAS_ACTION."""
    g = graph or get_graph()
    cypher = "MATCH (i:Incident), (a:Action) WHERE (i.id = $iid OR i.id = ('inc-' + $iid)) AND a.id = $aid MERGE (i)-[:HAS_ACTION]->(a)"
    g.query(cypher, {"iid": incident_id, "aid": action_id})


def create_incident(incident_id: str, service_name: str, cve: str, graph: Optional[Graph] = None) -> None:
    """Create a new open Incident node affecting the specified service in FalkorDB."""
    g = graph or get_graph()
    cypher = (
        "MERGE (inc:Incident {id: $iid}) SET inc.service_id = $svc, inc.cve = $cve, inc.status = 'open' "
        "WITH inc MATCH (s:Service) WHERE s.name = $svc OR s.id = $svc MERGE (inc)-[:AFFECTS]->(s)"
    )
    g.query(cypher, {"iid": incident_id, "svc": service_name, "cve": cve})


def close_incident(incident_id: str, status: str = "contained", graph: Optional[Graph] = None) -> None:
    """Update an Incident node status to contained or resolved in FalkorDB."""
    (graph or get_graph()).query("MATCH (inc:Incident) WHERE inc.id = $iid OR inc.id = ('inc-' + $iid) SET inc.status = $status", {"iid": incident_id, "status": status})


def get_incident(incident_id: str, graph: Optional[Graph] = None) -> Optional[dict]:
    """Retrieve an incident node by id."""
    res = (graph or get_graph()).query("MATCH (inc:Incident) WHERE inc.id = $iid OR inc.id = ('inc-' + $iid) RETURN inc.id, inc.status, inc.service_id, inc.cve LIMIT 1", {"iid": incident_id}).result_set
    return {"id": res[0][0], "status": res[0][1], "service_id": res[0][2], "cve": res[0][3]} if res else None


def get_incident_actions(incident_id: str, graph: Optional[Graph] = None) -> List[dict]:
    """Retrieve all Action nodes attached to an Incident node."""
    res = (graph or get_graph()).query("MATCH (i:Incident)-[:HAS_ACTION]->(a:Action) WHERE i.id = $iid OR i.id = ('inc-' + $iid) RETURN a.id, a.type, a.target, a.status, a.log", {"iid": incident_id}).result_set
    return [{"id": r[0], "type": r[1], "target": r[2], "status": r[3], "log": r[4]} for r in res]


def get_all_services(graph: Optional[Graph] = None) -> List[str]:
    """Retrieve all service names from FalkorDB."""
    res = (graph or get_graph()).query("MATCH (s:Service) RETURN DISTINCT coalesce(s.name, s.id) ORDER BY s.name").result_set
    return [str(r[0]) for r in res] if res else ["payments-api"]


def get_all_cves(graph: Optional[Graph] = None) -> List[str]:
    """Retrieve all vulnerability CVE IDs from FalkorDB."""
    res = (graph or get_graph()).query("MATCH (v:Vulnerability) RETURN DISTINCT v.cve_id ORDER BY v.cve_id").result_set
    return [str(r[0]) for r in res] if res else ["CVE-2024-3094"]
