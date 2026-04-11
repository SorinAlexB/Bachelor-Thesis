#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

#include "mitre_graph.hpp"
#include "pattern_matcher.hpp"

namespace py = pybind11;

PYBIND11_MODULE(security_cpp, m) {
    m.doc() = "C++ extensions for the security AI pipeline: MITRE A* graph and Aho-Corasick pattern matching";

    // ─── PathResult ──────────────────────────────────────────────────────────
    py::class_<PathResult>(m, "PathResult")
        .def_readonly("technique_ids", &PathResult::technique_ids,
            "Ordered list of MITRE technique IDs forming the attack path")
        .def_readonly("total_cost",    &PathResult::total_cost,
            "Total path cost (lower = more efficient / stealthy)")
        .def_readonly("found",         &PathResult::found,
            "True if a path was found")
        .def("__repr__", [](const PathResult& r) {
            std::string ids = "[";
            for (size_t i = 0; i < r.technique_ids.size(); i++) {
                if (i) ids += ", ";
                ids += "\"" + r.technique_ids[i] + "\"";
            }
            ids += "]";
            return "PathResult(found=" + std::string(r.found ? "True" : "False") +
                   ", cost=" + std::to_string(r.total_cost) +
                   ", path=" + ids + ")";
        });

    // ─── MITREGraph ───────────────────────────────────────────────────────────
    py::class_<MITREGraph>(m, "MITREGraph",
        "MITRE ATT&CK technique graph with A* and Dijkstra pathfinding")
        .def(py::init<>())
        .def("add_technique",
            &MITREGraph::add_technique,
            py::arg("id"),
            py::arg("name"),
            py::arg("tactic"),
            py::arg("platforms"),
            py::arg("prerequisites"),
            py::arg("stealth_score") = 0.5f,
            "Add a technique node to the graph")
        .def("add_edge",
            &MITREGraph::add_edge,
            py::arg("src"),
            py::arg("dst"),
            py::arg("weight") = 1.0f,
            "Add a directed edge between two technique nodes")
        .def("build_default_edges",
            &MITREGraph::build_default_edges,
            "Auto-generate edges based on kill-chain tactic ordering")
        .def("astar",
            &MITREGraph::astar,
            py::arg("start_id"),
            py::arg("goal_tactic"),
            py::arg("platform_filter") = "",
            py::arg("stealth_weight") = 0.4f,
            "A* search from start technique to goal tactic. Returns PathResult.")
        .def("shortest_path",
            &MITREGraph::shortest_path,
            py::arg("src_id"),
            py::arg("dst_id"),
            "Dijkstra shortest path between two technique IDs. Returns PathResult.")
        .def("techniques_by_tactic",
            &MITREGraph::techniques_by_tactic,
            py::arg("tactic"),
            "Return all technique IDs for the given tactic")
        .def("techniques_by_platform",
            &MITREGraph::techniques_by_platform,
            py::arg("platform"),
            "Return all technique IDs applicable to the given platform")
        .def("has_technique", &MITREGraph::has_technique, py::arg("id"))
        .def("node_count",    &MITREGraph::node_count)
        .def("edge_count",    &MITREGraph::edge_count)
        .def("__repr__", [](const MITREGraph& g) {
            return "MITREGraph(nodes=" + std::to_string(g.node_count()) +
                   ", edges=" + std::to_string(g.edge_count()) + ")";
        });

    // ─── Match ────────────────────────────────────────────────────────────────
    py::class_<Match>(m, "Match",
        "A pattern match result: (pattern, start_offset, end_offset)")
        .def_readonly("pattern", &Match::pattern)
        .def_readonly("start",   &Match::start)
        .def_readonly("end",     &Match::end)
        .def("__repr__", [](const Match& m) {
            return "Match(pattern=\"" + m.pattern + "\", start=" +
                   std::to_string(m.start) + ", end=" + std::to_string(m.end) + ")";
        })
        .def("__iter__", [](const Match& m) {
            // Allow tuple unpacking: pattern, start, end = match
            std::vector<py::object> items = {
                py::str(m.pattern),
                py::int_(m.start),
                py::int_(m.end),
            };
            return py::iter(py::cast(items));
        });

    // ─── PatternMatcher ───────────────────────────────────────────────────────
    py::class_<PatternMatcher>(m, "PatternMatcher",
        "Aho-Corasick multi-pattern matcher with parallel search support")
        .def(py::init<const std::vector<std::string>&>(),
            py::arg("patterns"),
            "Build the automaton from a list of patterns")
        .def("search",
            &PatternMatcher::search,
            py::arg("text"),
            "Search a single text. Returns list of Match objects.")
        .def("search_parallel",
            [](const PatternMatcher& pm, const std::vector<std::string>& texts) {
                // Release GIL during C++ parallel work
                std::vector<std::vector<Match>> results;
                {
                    py::gil_scoped_release release;
                    results = pm.search_parallel(texts);
                }
                return results;
            },
            py::arg("texts"),
            "Search multiple texts in parallel using std::thread. Returns list of lists of Match.")
        .def("pattern_count", &PatternMatcher::pattern_count)
        .def("__repr__", [](const PatternMatcher& pm) {
            return "PatternMatcher(patterns=" + std::to_string(pm.pattern_count()) + ")";
        });
}
