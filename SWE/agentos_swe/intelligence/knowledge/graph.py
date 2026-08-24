"""
M21 Security Knowledge Graph.

Provides an in-memory graph representation connecting repositories, findings, root causes,
sources, sinks, attack paths, remediations, frameworks, release outcomes, and regressions.
Supports deterministic graph traversal with MAX_KNOWLEDGE_GRAPH_DEPTH = 8.
"""

from typing import List, Dict, Any, Optional, Set


class SecurityKnowledgeGraph:
    """
    Knowledge graph linking security entities and relationships.
    """

    MAX_KNOWLEDGE_GRAPH_DEPTH: int = 8

    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, label: str, node_type: str, properties: Optional[Dict[str, Any]] = None) -> None:
        self.nodes[node_id] = {
            "id": node_id,
            "label": label,
            "type": node_type,
            "properties": properties or {},
        }

    def add_edge(self, source_id: str, target_id: str, relationship: str) -> None:
        self.edges.append({
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
        })

    def traverse(self, start_node_id: str, max_depth: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Performs deterministic breadth-first graph traversal up to max_depth (capped at 8).
        """
        depth_limit = min(max_depth or self.MAX_KNOWLEDGE_GRAPH_DEPTH, self.MAX_KNOWLEDGE_GRAPH_DEPTH)
        visited: Set[str] = set()
        queue = [(start_node_id, 0)]
        traversed_nodes: List[Dict[str, Any]] = []

        while queue:
            curr_id, depth = queue.pop(0)
            if curr_id in visited or depth > depth_limit:
                continue

            visited.add(curr_id)
            if curr_id in self.nodes:
                traversed_nodes.append(self.nodes[curr_id])

            # Find connected nodes
            for edge in self.edges:
                if edge["source"] == curr_id and edge["target"] not in visited:
                    queue.append((edge["target"], depth + 1))
                elif edge["target"] == curr_id and edge["source"] not in visited:
                    queue.append((edge["source"], depth + 1))

        return traversed_nodes
