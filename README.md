# 🛡️ Reachability: Autonomous CVE Commander

> **Autonomous incident response commander that grounds every security mitigation decision in verified FalkorDB graph topology and episodic incident memory.**

---

## 🎯 The Problem

Modern AI agents for SecOps and DevOps suffer from two fundamental flaws:
1. **Context Blindness**: Vector databases retrieve isolated text snippets by keyword similarity. They cannot traverse structural relationships—such as whether a compromised Kubernetes node has IAM permissions or network access to reach a crown-jewel database. Without graph topology, agents either miss multi-hop attack vectors or hallucinate ungrounded remediations.
2. **Episodic Amnesia**: Agents lose context between sessions. An agent will repeatedly attempt the same failing runbook procedure (e.g., dropping all ingress traffic and causing outage) because it has no structured memory connecting past incident failures to operational decisions.

**Reachability** solves this by putting **FalkorDB** at the center of the agent lifecycle: every decision must be grounded in an executable Cypher graph path, and every past resolution or failure is indexed in graph-native episodic memory.

---

## 🏗️ Architecture

```
+-------------------------------------------------------------+
|                      Streamlit UI                           |
|       (Incident Control · Timeline · Graph Evidence)        |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|               Orchestrator (orchestrator.py)                |
+--------+---------------------+---------------------+--------+
         |                     |                     |
         v                     v                     v
+-----------------+   +-----------------+   +-----------------+
| Security Agent  |   | Code Impact     |   | Commander Agent |
| (Blast Radius)  |   | Agent (Repo/Dev)|   | (Actions/Memory)|
+--------+--------+   +--------+--------+   +--------+--------+
         |                     |                     |
         +---------------------+---------------------+
                               |  Grounded Cypher Tools
                               v
+-------------------------------------------------------------+
|                      FalkorDB Graph                         |
|   +-----------------------+     +-----------------------+   |
|   |  Structural Context   |     |    Episodic Memory    |   |
|   |  (Topology/IAM/Code)  |     |   (Past Incidents)    |   |
|   +-----------------------+     +-----------------------+   |
+-------------------------------------------------------------+
```

---

## 📊 Graph Schema

The FalkorDB graph schema captures full-stack enterprise context:

### Node Labels
- `Service`: Software service (e.g., `payments-api`)
- `Asset`: Infrastructure hosts and databases (e.g., `k8s-node-payments-prod-01`, `rds-pg-payments-master`)
- `Vulnerability`: Known CVEs (e.g., `CVE-2024-3094`)
- `CrownJewel`: High-value data targets (e.g., `CustomerPIIStore`, `PaymentLedger`)
- `Identity` & `Permission`: IAM principals and policies (e.g., `role-payments-executor`)
- `Repo`, `File`, `Function`: Code exposure hierarchy
- `Owner` & `OnCall`: Engineering ownership and paging rotations
- `Incident`, `Action`, `RunbookStep`: Incident state and audit logs
- `MemoryEpisode`: Historical incident outcomes and lessons learned

### Relationship Types
- `(Service)-[:RUNS_ON]->(Asset)`
- `(Asset)-[:REACHES]->(CrownJewel)`
- `(Asset)-[:HAS_VULN]->(Vulnerability)`
- `(Asset)-[:USES_IDENTITY]->(Identity)-[:HAS_PERMISSION]->(Permission)-[:GRANTS_ACCESS_TO]->(CrownJewel)`
- `(Service)-[:HAS_REPO]->(Repo)-[:CONTAINS]->(File)-[:DEFINES]->(Function)`
- `(Service)-[:OWNED_BY]->(Owner)-[:ON_CALL]->(OnCall)`
- `(Incident)-[:AFFECTS]->(Service)`
- `(Incident)-[:HAS_ACTION]->(Action)`
- `(Incident)-[:FOLLOWS]->(RunbookStep)`
- `(Incident)-[:REMEMBERS]->(MemoryEpisode)-[:SIMILAR_TO]->(Incident)`

---

## 🤖 Agent Roles & Tool Registry

All agents extend `BaseAgent` and enforce strict graph-grounding: **if no verified `GraphPath` justifies the conclusion, the response is rejected as an error rather than fabricating an answer**.

| Agent | Responsibility | Registered Tools |
|---|---|---|
| **Security Agent** | Analyzes CVE blast radius, infrastructure exposure, and multi-hop attack paths to Crown Jewels. | `find_attack_paths`, `rank_cves_by_reachability`, `get_affected_assets` |
| **Code Impact Agent** | Identifies affected repositories, source files, patch candidates, and on-call engineers. | `get_code_impact`, `get_owners_and_oncall` |
| **Commander Agent** | Evaluates episodic memory, coordinates mitigation action sequence, and writes back incident memories. | `recall_for_decision`, `isolate_host`, `open_ticket`, `page_on_call`, `start/switch_runbook_step`, `post_incident_update`, `remember` |

---

## 🧠 How Memory Changes Behavior (Concrete Example)

During an active incident on `payments-api` with `CVE-2024-3094`:
1. The default runbook recommends: **`Apply strict WAF ingress drop rule`**.
2. Commander calls `recall_for_decision("payments-api", current_runbook_step="Apply strict WAF ingress drop rule")`.
3. FalkorDB traverses `(Service)-[:REMEMBERS]->(MemoryEpisode)` and discovers `mem-ep-payments-01`:
   - Outcome: Ingress blocking caused severe merchant webhook timeouts and payment delivery failures.
   - Status: `FAILED`.
4. The memory recall returns `recommendation: "switch_step"` with the graph path linking the failure.
5. **The Commander diverts remediation** to: **`VPC Security Group Egress Lockdown`**.
6. The action sequence executes, logs the switch reason citing `mem-ep-payments-01`, and commits a new successful memory episode to FalkorDB for future sessions.

---

## 🚀 How to Run

### 1. Prerequisites & Environment
Ensure Docker is installed and create your `.env`:
```bash
cp .env.example .env
# Configure OLLAMA_API_KEY in .env
```

### 2. Start FalkorDB
```bash
docker compose up -d
```

### 3. Initialize Schema & Seed Data
```bash
python -m src.schema --seed
```

### 4. Run Pytest Suite (32 passing tests)
```bash
pytest tests/ -v
```

### 5. Launch Streamlit UI
```bash
streamlit run app/streamlit_app.py
```

### 6. Alternative: Run via CLI
```bash
python -m src.orchestrator payments-api CVE-2024-3094
```

---

## 🛠️ Tech Stack

- **Graph Database**: FalkorDB (in-memory graph database running Cypher)
- **Language & Model**: Python 3.13, Ollama Cloud (`gemma4:31b-cloud` via OpenAI-compatible tool-calling)
- **Data Validation**: Pydantic v2 & Pydantic-Settings
- **User Interface**: Streamlit
- **Testing**: Pytest

---

## 🏆 Hackathon Track Alignment

- **Track 01 Primary (Context for AI Agents)**: Demonstrates deterministic structural context where agents navigate IAM permissions, host reachability, and code ownership directly in the graph to eliminate hallucinations.
- **Track 02 Secondary (Agent Memory)**: Implements graph-native episodic memory (`MemoryEpisode` nodes with `REMEMBERS` and `SIMILAR_TO` edges) allowing agents to learn from past incident failures and alter runbook decisions dynamically.
