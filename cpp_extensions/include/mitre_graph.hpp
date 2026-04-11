#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>

struct Technique {
    std::string id;
    std::string name;
    std::string tactic;
    std::vector<std::string> platforms;
    std::vector<std::string> prerequisites;
    float stealth_score = 0.5f;  // 0.0 = noisy, 1.0 = stealthy
};

struct Edge {
    std::string dst;
    float weight;
};

struct PathResult {
    std::vector<std::string> technique_ids;
    float total_cost;
    bool found;
};

class MITREGraph {
public:
    MITREGraph() = default;

    // Build the graph
    void add_technique(
        const std::string& id,
        const std::string& name,
        const std::string& tactic,
        const std::vector<std::string>& platforms,
        const std::vector<std::string>& prerequisites,
        float stealth_score = 0.5f
    );

    void add_edge(const std::string& src, const std::string& dst, float weight = 1.0f);

    void build_default_edges();  // Auto-build edges based on kill-chain tactic ordering

    // Pathfinding
    PathResult astar(
        const std::string& start_id,
        const std::string& goal_tactic,
        const std::string& platform_filter = "",
        float stealth_weight = 0.4f
    ) const;

    PathResult shortest_path(
        const std::string& src_id,
        const std::string& dst_id
    ) const;

    // Queries
    std::vector<std::string> techniques_by_tactic(const std::string& tactic) const;
    std::vector<std::string> techniques_by_platform(const std::string& platform) const;
    bool has_technique(const std::string& id) const;
    int node_count() const;
    int edge_count() const;

private:
    std::unordered_map<std::string, Technique> nodes_;
    std::unordered_map<std::string, std::vector<Edge>> adj_;

    static const std::vector<std::string> TACTIC_ORDER;

    float heuristic(const std::string& id, const std::string& goal_tactic) const;
    int tactic_index(const std::string& tactic) const;
};
