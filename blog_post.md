# Why Your Agent Needs a Graph, Not Just a Vector Store

When building autonomous AI agents for high-stakes operational environments like security incident response, the industry standard has defaulted to vector retrieval. You take runbooks, post-mortems, and infrastructure docs, chunk them into 500-token blocks, generate embeddings, and query them using cosine similarity.

In prototype chat bots, this looks impressive. But when an agent is given access to tools that isolate cloud instances, update firewall rules, and page on-call engineers, vector retrieval rapidly falls apart. 

Here is why your agent needs a graph database—and what we learned building **CVE Commander** on top of **FalkorDB**.

---

## 1. The Context Problem

Vector databases answer the question: *"Which text paragraphs sound semantically similar to this user prompt?"*

In incident response, that is almost never the question that needs answering. The questions that matter are structural:
- Can the server hosting this service communicate over the network with our customer PII database?
- Does the service account attached to this Kubernetes pod possess permissions to read secret keys in the ledger?
- Which repository and functions define this endpoint, and who is on call right now for that specific component?

When an LLM tries to answer these questions using vector search, it retrieves disconnected fragments. A document might mention `payments-api`, and another document might mention `CustomerPIIStore`. The vector store happily surfaces both chunks. The LLM then hallucinates an attack path that does not exist in reality, or fails to spot a real path buried across four hops of IAM roles and security groups.

Without structural context, agents are guessing.

---

## 2. Why Relationships Matter

Graphs treat relationships as first-class citizens. Instead of hoping an embedding space captures multi-hop network accessibility, we model reality directly in FalkorDB:

```
(Service)-[:RUNS_ON]->(Asset)-[:REACHES]->(CrownJewel)
```

Or through IAM privilege chains:

```
(Asset)-[:USES_IDENTITY]->(Identity)-[:HAS_PERMISSION]->(Permission)-[:GRANTS_ACCESS_TO]->(CrownJewel)
```

In Cypher, finding every attack path from a service to a Crown Jewel is a single deterministic query:

```python
def find_attack_paths(service_name: str, graph: Optional[Graph] = None) -> List[AttackPath]:
    """Find shortest traversable attack paths from a service's assets to crown jewels."""
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
    # Assemble structured AttackPath models
    ...
```

When our Security Agent invokes this tool, it does not receive ambiguous text. It receives an exact sequence of node identifiers and relationship types. If the path does not exist in FalkorDB, the agent cannot pretend it does.

---

## 3. The Build

We structured CVE Commander into three focused agents coordinating through an orchestrator:

1. **Security Agent**: Specializes in blast radius. It inspects vulnerable assets hosting the service and computes shortest attack paths to Crown Jewels.
2. **Code Impact Agent**: Maps the service to its code repository (`Repo → File → Function`), identifies the primary patch target, and resolves the engineer on call:

```python
def get_code_impact(service_name: str, graph: Optional[Graph] = None) -> Optional[CodeImpact]:
    """Map a service to its repository, exposed files, functions, owner, and on-call rotation."""
    g = graph or get_graph()
    cypher = (
        "MATCH (s:Service)-[:HAS_REPO]->(r:Repo) WHERE s.name = $svc OR s.id = $svc "
        "OPTIONAL MATCH (r)-[:CONTAINS]->(f:File) OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function) "
        "OPTIONAL MATCH (s)-[:OWNED_BY]->(o:Owner) OPTIONAL MATCH (o)-[:ON_CALL]->(oc:OnCall) "
        "RETURN s.name, r.name, collect(DISTINCT f.path), collect(DISTINCT fn.name), "
        "coalesce(o.name, 'Unassigned'), coalesce(oc.name, 'Unassigned') LIMIT 1"
    )
    res = g.query(cypher, {"svc": service_name.strip()}).result_set
    ...
```

3. **Commander Agent**: Responsible for operational remediation. It takes the output of the first two agents, evaluates historical memory, and dispatches audited actions: isolating hosts, opening Jira tickets, paging engineers, and managing runbooks.

---

## 4. What Memory Did

Most AI agent demonstrations suffer from what we call "episodic amnesia." Each session begins with a clean slate.

In our production scenario on `payments-api` with `CVE-2024-3094`, the standard mitigation runbook specifies:
> *Step 1: Apply strict WAF ingress drop rule.*

If an agent blindly executes this runbook step, it cuts off inbound traffic. But in a past incident on `payments-api` (recorded as episode `mem-ep-payments-01`), doing this broke external webhook callbacks from payment gateways, creating an immediate outage.

In a vector store setup, searching for "mitigate CVE on payments" would likely retrieve the standard runbook, completely missing the nuanced context that this step failed previously for this specific architecture.

With FalkorDB, we implemented graph-native episodic memory:

```python
def link_memory_episode(episode_id: str, service_name: str, incident_id: Optional[str] = None, graph: Optional[Graph] = None) -> None:
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
```

Before committing to an action, the Commander runs `recall_for_decision("payments-api", "Apply strict WAF ingress drop rule")`. The query inspects prior episodes linked via `SIMILAR_TO` edges. Seeing that the step previously failed with collateral damage, the tool explicitly returns:

```json
{
  "recommendation": "switch_step",
  "relevant_episode": "mem-ep-payments-01",
  "reason": "Past episode recorded that ingress blocking broke webhooks. Divert to egress lockdown."
}
```

The agent is forced by its grounding rules to switch to `VPC Security Group Egress Lockdown`. It mitigates the threat, preserves customer traffic, and writes a new `MemoryEpisode` into FalkorDB documenting the success.

---

## 5. The Explanation Layer

A black-box decision is unusable in enterprise infrastructure. If an automated agent disconnects a server or pages a staff engineer at midnight, it must present unassailable justification.

Because our agent's reasoning is tied to graph paths, the explanation layer is built-in:

```
payments-api → RUNS_ON → k8s-node-payments-prod-01 → REACHES → CustomerPIIStore
```

The Streamlit UI displays this exact sequence for every mitigation action. The user does not have to trust the LLM's summary; they can see the structural traversal that triggered the isolation.

---

## 6. Lessons Learned

1. **Strict Path Enforcement Beats Prompt Engineering**: Telling an LLM "only use verified information" in a prompt is ineffective. In `BaseAgent`, we enforced a programmatic rule: if an agent's final output does not contain an executable `GraphPath`, the run is marked as an error. Hallucinations dropped to zero.
2. **In-Memory Graphs Match LLM Speed**: FalkorDB’s low-latency execution allowed our agents to perform multi-hop graph traversals within the same reasoning loop without noticeable lag.
3. **Graph Memory Outlives Context Windows**: Long conversation histories quickly hit token limits and introduce prompt degradation. Offloading incident outcomes to graph nodes connected by typed relationships creates clean, queryable long-term memory.

If you are building autonomous agents that take real-world actions, text similarity is not enough. Give your agents a graph.
