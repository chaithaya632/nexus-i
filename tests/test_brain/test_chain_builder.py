"""Tests for nexus.brain.chain_builder."""

from nexus.brain.chain_builder import ChainBuilder


class TestChainBuilder:
    def test_default_graph(self):
        cb = ChainBuilder()
        cb.build_default_graph()
        assert cb.node_count > 10
        assert cb.edge_count > 20

    def test_find_attack_paths(self):
        cb = ChainBuilder()
        cb.build_default_graph()

        paths = cb.find_attack_paths("service_http", "rce_achieved")
        assert len(paths) > 0
        # Each path is a list of steps
        for path in paths:
            assert path[0]["from"] == "service_http"
            assert path[-1]["to"] == "rce_achieved"

    def test_find_no_path(self):
        cb = ChainBuilder()
        cb.build_default_graph()
        paths = cb.find_attack_paths("nonexistent_state", "rce_achieved")
        assert len(paths) == 0

    def test_find_all_goals(self):
        cb = ChainBuilder()
        cb.build_default_graph()
        goals = cb.find_all_goals_from("service_http")
        assert "rce_achieved" in goals

    def test_suggest_next_actions(self):
        cb = ChainBuilder()
        cb.build_default_graph()
        suggestions = cb.suggest_next_actions(["service_http"])
        assert len(suggestions) > 0
        # Suggestions should be sorted by weight
        weights = [s["weight"] for s in suggestions]
        assert weights == sorted(weights)

    def test_add_custom_edge(self):
        cb = ChainBuilder()
        cb.add_edge("state_a", "state_b", action="test", tool="custom", weight=0.5)
        assert cb.node_count == 2
        assert cb.edge_count == 1

    def test_stats(self):
        cb = ChainBuilder()
        cb.build_default_graph()
        stats = cb.stats()
        assert "nodes" in stats
        assert "edges" in stats
        assert "templates" in stats
        assert stats["nodes"] > 0

    def test_weight_clamping(self):
        cb = ChainBuilder()
        cb.add_edge("a", "b", action="test", weight=-1.0)
        cb.add_edge("b", "c", action="test", weight=5.0)
        # Weights should be clamped to [0.01, 1.0]
        assert cb._graph.edges["a", "b"]["weight"] == 0.01
        assert cb._graph.edges["b", "c"]["weight"] == 1.0
