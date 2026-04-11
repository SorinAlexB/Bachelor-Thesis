#include "pattern_matcher.hpp"

#include <algorithm>
#include <queue>
#include <thread>
#include <mutex>

// ─── Aho-Corasick construction ────────────────────────────────────────────────

AhoCorasick::AhoCorasick(const std::vector<std::string>& patterns)
    : patterns_(patterns)
{
    build();
}

void AhoCorasick::build() {
    automaton_.clear();
    automaton_.emplace_back();  // root state 0

    // Build trie
    for (int pi = 0; pi < (int)patterns_.size(); pi++) {
        int cur = 0;
        for (char c : patterns_[pi]) {
            auto it = automaton_[cur].next.find(c);
            if (it == automaton_[cur].next.end()) {
                automaton_[cur].next[c] = (int)automaton_.size();
                automaton_.emplace_back();
                cur = (int)automaton_.size() - 1;
            } else {
                cur = it->second;
            }
        }
        automaton_[cur].output.push_back(pi);
    }

    // Build failure links via BFS
    std::queue<int> bfs;
    for (auto& [c, s] : automaton_[0].next) {
        automaton_[s].fail = 0;
        bfs.push(s);
    }

    while (!bfs.empty()) {
        int r = bfs.front(); bfs.pop();
        for (auto& [c, s] : automaton_[r].next) {
            bfs.push(s);
            int f = automaton_[r].fail;
            while (f != 0 && !automaton_[f].next.count(c)) {
                f = automaton_[f].fail;
            }
            auto it = automaton_[f].next.find(c);
            automaton_[s].fail = (it != automaton_[f].next.end() && it->second != s)
                                  ? it->second : 0;
            // Merge output with fail state output
            const auto& fail_out = automaton_[automaton_[s].fail].output;
            automaton_[s].output.insert(
                automaton_[s].output.end(),
                fail_out.begin(), fail_out.end()
            );
        }
    }
}

// ─── Aho-Corasick search ──────────────────────────────────────────────────────

std::vector<Match> AhoCorasick::search(const std::string& text) const {
    std::vector<Match> matches;
    int state = 0;

    for (size_t i = 0; i < text.size(); i++) {
        char c = text[i];

        while (state != 0 && !automaton_[state].next.count(c)) {
            state = automaton_[state].fail;
        }
        auto it = automaton_[state].next.find(c);
        if (it != automaton_[state].next.end()) {
            state = it->second;
        }

        for (int pi : automaton_[state].output) {
            size_t len = patterns_[pi].size();
            matches.push_back({patterns_[pi], i + 1 - len, i + 1});
        }
    }

    return matches;
}

// ─── PatternMatcher ───────────────────────────────────────────────────────────

PatternMatcher::PatternMatcher(const std::vector<std::string>& patterns)
    : ac_(patterns), patterns_(patterns)
{}

std::vector<Match> PatternMatcher::search(const std::string& text) const {
    return ac_.search(text);
}

std::vector<std::vector<Match>> PatternMatcher::search_parallel(
    const std::vector<std::string>& texts
) const {
    std::vector<std::vector<Match>> results(texts.size());

    // Use hardware_concurrency threads
    unsigned int nthreads = std::max(1u, std::thread::hardware_concurrency());
    nthreads = std::min(nthreads, (unsigned int)texts.size());

    std::vector<std::thread> threads;
    std::atomic<size_t> next_idx{0};

    auto worker = [&]() {
        while (true) {
            size_t idx = next_idx.fetch_add(1);
            if (idx >= texts.size()) break;
            results[idx] = ac_.search(texts[idx]);
        }
    };

    for (unsigned int t = 0; t < nthreads; t++) {
        threads.emplace_back(worker);
    }
    for (auto& t : threads) {
        t.join();
    }

    return results;
}

int PatternMatcher::pattern_count() const {
    return (int)patterns_.size();
}
