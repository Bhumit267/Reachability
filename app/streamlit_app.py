"""Streamlit web dashboard for autonomous CVE incident command and graph reachability."""

import sys
from pathlib import Path
from typing import List

# Ensure project root is in sys.path when running via streamlit run
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from src.models import GraphPath, IncidentRun
from src.orchestrator import run_incident
from src.queries import get_all_cves, get_all_services, get_cves_for_service
from src.schema import reset_graph

st.set_page_config(page_title="CVE Commander · Reachability", layout="wide", initial_sidebar_state="collapsed")


def format_arrow_path(path: GraphPath) -> str:
    """Format a GraphPath into a standard readable sequence."""
    if not path or not path.nodes:
        return path.readable if path else "No path recorded"
    if "→" in path.readable or "<-" in path.readable:
        return path.readable
    elements: List[str] = []
    for i, edge in enumerate(path.edges):
        node = path.nodes[i] if i < len(path.nodes) else "?"
        elements.extend([node, edge])
    if len(path.nodes) > len(path.edges):
        elements.append(path.nodes[-1])
    return " → ".join(elements)


# Top bar
top_c1, top_c2, top_c3 = st.columns([3, 2, 1])
with top_c1:
    st.title("🛡️ Reachability: CVE Commander")
with top_c2:
    st.markdown("### `Track 01 primary · Track 02 memory`")
with top_c3:
    if st.button("🔄 Reset Graph", help="Wipe and reload FalkorDB seed data"):
        with st.spinner("Resetting graph..."):
            reset_graph()
            st.session_state.clear()
            st.success("Graph reset to initial seed!")
            st.rerun()

st.divider()

col_control, col_timeline, col_evidence = st.columns([1, 1.2, 1.3], gap="medium")

# Left column — Incident Control
with col_control:
    st.subheader("⚡ Incident Control")
    services = get_all_services()
    selected_service = st.selectbox("Target Service", options=services, index=0 if services else 0)

    # Dynamically scope CVEs to the chosen service
    service_cves = get_cves_for_service(selected_service)
    cves = service_cves if service_cves else get_all_cves()
    selected_cve = st.selectbox("Target Vulnerability", options=cves, index=0 if cves else 0)

    if st.button("🚀 Run Incident", type="primary", use_container_width=True):
        with st.spinner(f"Investigating {selected_service} ({selected_cve}) via autonomous agents..."):
            run_result: IncidentRun = run_incident(service=selected_service, cve=selected_cve)
            st.session_state["incident_run"] = run_result

    if "incident_run" in st.session_state:
        run: IncidentRun = st.session_state["incident_run"]
        if run.status == "contained":
            st.success(f"Incident `{run.incident_id}` Contained")
        else:
            st.error(f"Incident `{run.incident_id}`: Failed / Escalated")
        st.markdown(f"**Service:** `{run.service}`")
        st.markdown(f"**CVE:** `{run.cve}`")
        st.markdown(f"**Status:** `{run.status.upper()}`")
        if run.memory_written:
            st.markdown(f"**Persisted Memory:** `{run.memory_written}`")

# Middle column — Timeline
with col_timeline:
    st.subheader("⏱️ Incident Timeline")
    if "incident_run" in st.session_state:
        run: IncidentRun = st.session_state["incident_run"]
        for idx, act in enumerate(run.timeline, 1):
            act_type = act.get("action_type", "ACTION")
            target = act.get("target", "N/A")
            status = act.get("status", "SUCCESS")
            ts = act.get("timestamp", "")[:19].replace("T", " ")

            badge = "🟢" if status == "SUCCESS" else "🔴"
            with st.expander(f"{badge} {idx}. {act_type} → {target}", expanded=(idx in (1, 4))):
                st.caption(f"**Timestamp:** {ts} | **Status:** {status}")
                st.info(act.get("log_line", ""))

                # Show relevant graph path if matching
                matching_path = None
                if act_type == "ISOLATE_HOST" and run.blast_radius.graph_path:
                    matching_path = run.blast_radius.graph_path
                elif act_type in ("OPEN_TICKET", "PAGE_ONCALL") and run.code_impact.graph_path:
                    matching_path = run.code_impact.graph_path
                elif act_type == "SWITCH_RUNBOOK_STEP" and len(run.commander_result.graph_paths) > 2:
                    matching_path = run.commander_result.graph_paths[2]

                if matching_path:
                    st.caption("Grounded Graph Justification:")
                    st.code(format_arrow_path(matching_path), language="text")
    else:
        st.info("Run an incident from the left column to view the chronological action timeline.")

# Right column — Graph Evidence
with col_evidence:
    st.subheader("🔍 Graph Evidence & Memory")
    if "incident_run" in st.session_state:
        run: IncidentRun = st.session_state["incident_run"]

        # Memory influence callout
        mem_inf = run.commander_result.memory_influence
        if "Memory recall alert" in mem_inf or "Switched" in mem_inf:
            st.warning(f"**🧠 Memory Influence Callout**\n\n{mem_inf}")
        else:
            st.info(f"**🧠 Memory Recall Status:**\n\n{mem_inf}")

        st.markdown("#### 🎯 Traversed Graph Paths")
        for idx, path in enumerate(run.all_graph_paths, 1):
            st.markdown(f"**Path {idx}:**")
            st.code(format_arrow_path(path), language="text")

        with st.expander("Agent Reasoning Summaries", expanded=False):
            st.markdown(f"**Security Agent:**\n{run.blast_radius.answer}")
            st.markdown(f"**Code Impact Agent:**\n{run.code_impact.answer}")
            st.markdown(f"**Commander Summary:**\n{run.commander_result.summary}")
    else:
        st.info("Graph reachability paths and memory recall evidence will appear here after execution.")
