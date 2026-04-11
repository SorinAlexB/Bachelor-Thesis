#include "mitre_graph.hpp"

#include <algorithm>
#include <cmath>
#include <functional>
#include <limits>
#include <queue>
#include <stdexcept>

// Kill-chain tactic ordering (Lockheed Martin / MITRE kill chain)
const std::vector<std::string> MITREGraph::TACTIC_ORDER = {
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
};

// ─── Graph construction ───────────────────────────────────────────────────────

void MITREGraph::add_technique(
    const std::string& id,
    const std::string& name,
    const std::string& tactic,
    const std::vector<std::string>& platforms,
    const std::vector<std::string>& prerequisites,
    float stealth_score
) {
    nodes_[id] = {id, name, tactic, platforms, prerequisites, stealth_score};
    if (adj_.find(id) == adj_.end()) {
        adj_[id] = {};
    }
}

void MITREGraph::add_edge(const std::string& src, const std::string& dst, float weight) {
    adj_[src].push_back({dst, weight});
}

void MITREGraph::build_default_edges() {
    // Group techniques by tactic stage
    std::unordered_map<std::string, std::vector<std::string>> by_tactic;
    for (auto& [id, tech] : nodes_) {
        by_tactic[tech.tactic].push_back(id);
    }

    // Connect techniques in adjacent tactic stages
    for (size_t i = 0; i + 1 < TACTIC_ORDER.size(); i++) {
        const auto& cur_tactic  = TACTIC_ORDER[i];
        const auto& next_tactic = TACTIC_ORDER[i + 1];

        auto cur_it  = by_tactic.find(cur_tactic);
        auto next_it = by_tactic.find(next_tactic);
        if (cur_it == by_tactic.end() || next_it == by_tactic.end()) continue;

        for (const auto& src_id : cur_it->second) {
            for (const auto& dst_id : next_it->second) {
                // Edge weight: 1.0 base + stealth penalty
                float w = 1.0f + (1.0f - nodes_[dst_id].stealth_score);
                add_edge(src_id, dst_id, w);
            }
        }
    }

    // Also connect prerequisites
    for (auto& [id, tech] : nodes_) {
        for (const auto& prereq : tech.prerequisites) {
            if (nodes_.count(prereq)) {
                add_edge(prereq, id, 0.5f);
            }
        }
    }
}

// ─── A* search ────────────────────────────────────────────────────────────────

int MITREGraph::tactic_index(const std::string& tactic) const {
    auto it = std::find(TACTIC_ORDER.begin(), TACTIC_ORDER.end(), tactic);
    if (it == TACTIC_ORDER.end()) return (int)TACTIC_ORDER.size();
    return (int)(it - TACTIC_ORDER.begin());
}

float MITREGraph::heuristic(const std::string& id, const std::string& goal_tactic) const {
    auto it = nodes_.find(id);
    if (it == nodes_.end()) return 999.0f;
    int cur_idx  = tactic_index(it->second.tactic);
    int goal_idx = tactic_index(goal_tactic);
    // Admissible heuristic: steps remaining in kill chain × min edge weight
    int diff = goal_idx - cur_idx;
    return diff > 0 ? (float)diff * 0.5f : 0.0f;
}

PathResult MITREGraph::astar(
    const std::string& start_id,
    const std::string& goal_tactic,
    const std::string& platform_filter,
    float stealth_weight
) const {
    if (!nodes_.count(start_id)) {
        return {{}, 0.0f, false};
    }

    // Priority queue: (f_score, node_id)
    using PQEntry = std::pair<float, std::string>;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> open;

    std::unordered_map<std::string, float> g_score;
    std::unordered_map<std::string, std::string> came_from;
    std::unordered_set<std::string> closed;

    g_score[start_id] = 0.0f;
    float h = heuristic(start_id, goal_tactic);
    open.push({h, start_id});

    while (!open.empty()) {
        auto [f, current] = open.top();
        open.pop();

        if (closed.count(current)) continue;
        closed.insert(current);

        // Check if goal reached
        const auto& cur_tech = nodes_.at(current);

        // Platform filter
        if (!platform_filter.empty()) {
            bool ok = false;
            for (const auto& p : cur_tech.platforms) {
                if (p == platform_filter || p == "cross") { ok = true; break; }
            }
            if (!ok && current != start_id) continue;
        }

        if (cur_tech.tactic == goal_tactic && current != start_id) {
            // Reconstruct path
            std::vector<std::string> path;
            std::string node = current;
            while (came_from.count(node)) {
                path.push_back(node);
                node = came_from[node];
            }
            path.push_back(start_id);
            std::reverse(path.begin(), path.end());
            return {path, g_score[current], true};
        }

        auto adj_it = adj_.find(current);
        if (adj_it == adj_.end()) continue;

        for (const auto& edge : adj_it->second) {
            if (closed.count(edge.dst)) continue;
            if (!nodes_.count(edge.dst)) continue;

            // Incorporate stealth into edge weight
            const auto& dst_tech = nodes_.at(edge.dst);
            float stealth_penalty = stealth_weight * (1.0f - dst_tech.stealth_score);
            float tentative_g = g_score[current] + edge.weight + stealth_penalty;

            if (!g_score.count(edge.dst) || tentative_g < g_score[edge.dst]) {
                g_score[edge.dst] = tentative_g;
                came_from[edge.dst] = current;
                float h_val = heuristic(edge.dst, goal_tactic);
                open.push({tentative_g + h_val, edge.dst});
            }
        }
    }

    return {{}, 0.0f, false};
}

PathResult MITREGraph::shortest_path(
    const std::string& src_id,
    const std::string& dst_id
) const {
    if (!nodes_.count(src_id) || !nodes_.count(dst_id)) {
        return {{}, 0.0f, false};
    }

    // Dijkstra's algorithm
    using PQEntry = std::pair<float, std::string>;
    std::priority_queue<PQEntry, std::vector<PQEntry>, std::greater<PQEntry>> pq;
    std::unordered_map<std::string, float> dist;
    std::unordered_map<std::string, std::string> prev;

    dist[src_id] = 0.0f;
    pq.push({0.0f, src_id});

    while (!pq.empty()) {
        auto [d, u] = pq.top();
        pq.pop();

        if (d > dist[u]) continue;
        if (u == dst_id) break;

        auto adj_it = adj_.find(u);
        if (adj_it == adj_.end()) continue;

        for (const auto& edge : adj_it->second) {
            float nd = dist[u] + edge.weight;
            if (!dist.count(edge.dst) || nd < dist[edge.dst]) {
                dist[edge.dst] = nd;
                prev[edge.dst] = u;
                pq.push({nd, edge.dst});
            }
        }
    }

    if (!dist.count(dst_id)) return {{}, 0.0f, false};

    std::vector<std::string> path;
    std::string node = dst_id;
    while (prev.count(node)) {
        path.push_back(node);
        node = prev[node];
    }
    path.push_back(src_id);
    std::reverse(path.begin(), path.end());
    return {path, dist[dst_id], true};
}

// ─── Queries ─────────────────────────────────────────────────────────────────

std::vector<std::string> MITREGraph::techniques_by_tactic(const std::string& tactic) const {
    std::vector<std::string> result;
    for (const auto& [id, tech] : nodes_) {
        if (tech.tactic == tactic) result.push_back(id);
    }
    std::sort(result.begin(), result.end());
    return result;
}

std::vector<std::string> MITREGraph::techniques_by_platform(const std::string& platform) const {
    std::vector<std::string> result;
    for (const auto& [id, tech] : nodes_) {
        for (const auto& p : tech.platforms) {
            if (p == platform || p == "cross") {
                result.push_back(id);
                break;
            }
        }
    }
    std::sort(result.begin(), result.end());
    return result;
}

bool MITREGraph::has_technique(const std::string& id) const {
    return nodes_.count(id) > 0;
}

int MITREGraph::node_count() const {
    return (int)nodes_.size();
}

int MITREGraph::edge_count() const {
    int total = 0;
    for (const auto& [_, edges] : adj_) total += (int)edges.size();
    return total;
}
