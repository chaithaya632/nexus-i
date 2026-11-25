"""Attack chain builder — weighted graph + Dijkstra pathfinding."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import networkx as nx
import yaml


@dataclass
class ChainTemplate:
    """Pre-defined attack chain template from knowledge base."""
    name: str
    description: str = ""
    steps: list[dict[str, Any]] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    impact: str = "high"


class ChainBuilder:
    """Builds and discovers attack chains using a weighted directed graph.

    Nodes represent states (e.g., 'port_8080_open', 'sqli_confirmed', 'rce_achieved').
    Edges represent actions with weights (lower = more reliable).
    Dijkstra finds the optimal (most reliable) path from initial access to impact.
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()
        self._templates: list[ChainTemplate] = []

    @property
    def node_count(self) -> int:
        return self._graph.number_of_nodes()

    @property
    def edge_count(self) -> int:
        return self._graph.number_of_edges()

    def add_node(self, state: str, **attrs: Any) -> None:
        self._graph.add_node(state, **attrs)

    def add_edge(
        self,
        from_state: str,
        to_state: str,
        action: str,
        tool: str = "",
        weight: float = 0.5,
        description: str = "",
    ) -> None:
        """Add a transition edge. Weight: 0.0 (very reliable) to 1.0 (unreliable)."""
        self._graph.add_edge(
            from_state,
            to_state,
            action=action,
            tool=tool,
            weight=max(0.01, min(1.0, weight)),
            description=description,
        )

    def load_templates(self, knowledge_dir: Path) -> None:
        """Load chain templates from YAML files."""
        chains_dir = knowledge_dir / "chains"
        if not chains_dir.is_dir():
            return
        for yaml_file in sorted(chains_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (yaml.YAMLError, OSError):
                continue
            if not isinstance(raw, dict):
                continue
            for chain_name, chain_data in raw.get("chains", {}).items():
                if not isinstance(chain_data, dict):
                    continue
                tpl = ChainTemplate(
                    name=chain_data.get("name", chain_name),
                    description=chain_data.get("description", ""),
                    steps=chain_data.get("steps", []),
                    preconditions=chain_data.get("preconditions", []),
                    impact=chain_data.get("impact", "high"),
                )
                self._templates.append(tpl)
                self._template_to_graph(tpl)

    def _template_to_graph(self, tpl: ChainTemplate) -> None:
        """Convert a chain template into graph nodes and edges."""
        for i, step in enumerate(tpl.steps):
            condition = step.get("condition", f"step_{i}")
            action = step.get("action", "")
            tool = step.get("tool", "")
            next_state = step.get("next", f"step_{i + 1}")
            weight = step.get("weight", 0.5)

            self.add_node(condition)
            self.add_node(next_state)
            self.add_edge(condition, next_state, action=action, tool=tool, weight=weight)

    def build_default_graph(self) -> None:
        """Build the default attack progression graph."""
        edges = [
            # Recon → Service Discovery
            ("target_identified", "ports_discovered", "port_scan", "nmap", 0.1),
            ("ports_discovered", "services_identified", "service_enum", "nmap", 0.1),
            ("services_identified", "tech_fingerprinted", "tech_fingerprint", "whatweb", 0.15),

            # Web Application Paths
            ("service_http", "directories_found", "dir_bruteforce", "ffuf", 0.2),
            ("service_http", "vulns_scanned", "vuln_scan", "nuclei", 0.15),
            ("service_http", "sqli_found", "sqli_test", "sqlmap", 0.4),
            ("service_http", "xss_found", "xss_test", "dalfox", 0.4),
            ("sqli_found", "sqli_confirmed", "sqli_exploit", "sqlmap", 0.3),
            ("sqli_confirmed", "db_dumped", "db_dump", "sqlmap", 0.2),
            ("db_dumped", "credentials_obtained", "extract_creds", "sqlmap", 0.2),
            ("credentials_obtained", "admin_panel_access", "login_admin", "hydra", 0.3),
            ("admin_panel_access", "file_uploaded", "upload_shell", "custom", 0.4),
            ("file_uploaded", "rce_achieved", "execute_shell", "custom", 0.2),

            # Tomcat Paths
            ("service_tomcat", "tomcat_manager_found", "check_manager", "ffuf", 0.2),
            ("tomcat_manager_found", "tomcat_creds_found", "default_creds", "hydra", 0.3),
            ("tomcat_creds_found", "war_uploaded", "deploy_war", "msfconsole", 0.2),
            ("war_uploaded", "rce_achieved", "war_shell", "msfconsole", 0.1),
            ("service_tomcat", "ghostcat_vuln", "ghostcat_check", "nmap", 0.3),
            ("ghostcat_vuln", "config_leaked", "ghostcat_read", "custom", 0.3),
            ("config_leaked", "credentials_obtained", "parse_config", "custom", 0.2),

            # WordPress Paths
            ("service_wordpress", "wp_users_found", "wp_user_enum", "wpscan", 0.2),
            ("service_wordpress", "xmlrpc_enabled", "xmlrpc_check", "nuclei", 0.15),
            ("xmlrpc_enabled", "wp_creds_found", "xmlrpc_brute", "hydra", 0.5),
            ("wp_creds_found", "admin_panel_access", "wp_admin_login", "custom", 0.1),

            # Credential Reuse
            ("credentials_obtained", "ssh_access", "ssh_login", "ssh", 0.3),
            ("credentials_obtained", "rdp_access", "rdp_login", "xfreerdp", 0.4),
            ("ssh_access", "rce_achieved", "ssh_command", "ssh", 0.1),
            ("rdp_access", "rce_achieved", "rdp_command", "xfreerdp", 0.1),

            # SMB Paths
            ("service_smb", "smb_shares_found", "enum_shares", "crackmapexec", 0.2),
            ("service_smb", "null_session", "null_session_check", "enum4linux", 0.3),
            ("service_smb", "ms17_010_vuln", "eternalblue_check", "nmap", 0.3),
            ("ms17_010_vuln", "rce_achieved", "eternalblue_exploit", "msfconsole", 0.3),
            ("smb_shares_found", "sensitive_files", "read_shares", "smbclient", 0.4),
            ("sensitive_files", "credentials_obtained", "extract_creds", "custom", 0.3),

            # Post-Exploitation
            ("rce_achieved", "privesc_achieved", "privilege_escalation", "custom", 0.5),
            ("privesc_achieved", "data_exfiltrated", "data_collection", "custom", 0.3),
            ("rce_achieved", "lateral_movement", "pivot", "custom", 0.5),
        ]

        for from_s, to_s, action, tool, weight in edges:
            self.add_edge(from_s, to_s, action=action, tool=tool, weight=weight)

    def find_attack_paths(
        self, start: str, goal: str, max_paths: int = 5
    ) -> list[list[dict[str, Any]]]:
        """Find optimal attack paths from start to goal using Dijkstra.

        Returns list of paths, each path is a list of steps with
        {from, to, action, tool, weight}.
        """
        if start not in self._graph or goal not in self._graph:
            return []

        paths: list[list[dict[str, Any]]] = []
        try:
            for path_nodes in nx.shortest_simple_paths(
                self._graph, start, goal, weight="weight"
            ):
                steps = []
                for i in range(len(path_nodes) - 1):
                    edge = self._graph.edges[path_nodes[i], path_nodes[i + 1]]
                    steps.append({
                        "from": path_nodes[i],
                        "to": path_nodes[i + 1],
                        "action": edge.get("action", ""),
                        "tool": edge.get("tool", ""),
                        "weight": edge.get("weight", 1.0),
                    })
                paths.append(steps)
                if len(paths) >= max_paths:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            pass

        return paths

    def find_all_goals_from(self, start: str) -> list[str]:
        """Find all reachable goal states from a starting state."""
        if start not in self._graph:
            return []
        reachable = nx.descendants(self._graph, start)
        # Goals are states with no outgoing edges or high-impact states
        goals = {"rce_achieved", "data_exfiltrated", "privesc_achieved",
                 "admin_panel_access", "credentials_obtained", "lateral_movement"}
        return sorted(reachable & goals)

    def suggest_next_actions(self, current_states: list[str]) -> list[dict[str, Any]]:
        """Given current engagement states, suggest next actions."""
        suggestions: list[dict[str, Any]] = []
        for state in current_states:
            if state not in self._graph:
                continue
            for _, neighbor, edge_data in self._graph.out_edges(state, data=True):
                suggestions.append({
                    "from_state": state,
                    "to_state": neighbor,
                    "action": edge_data.get("action", ""),
                    "tool": edge_data.get("tool", ""),
                    "weight": edge_data.get("weight", 1.0),
                    "description": edge_data.get("description", ""),
                })
        suggestions.sort(key=lambda s: s["weight"])
        return suggestions

    def stats(self) -> dict[str, int]:
        return {
            "nodes": self.node_count,
            "edges": self.edge_count,
            "templates": len(self._templates),
        }
