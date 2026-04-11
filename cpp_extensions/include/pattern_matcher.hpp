#pragma once

#include <string>
#include <vector>
#include <unordered_map>

struct Match {
    std::string pattern;
    size_t start;
    size_t end;
};

// Aho-Corasick automaton for multi-pattern string matching
class AhoCorasick {
public:
    explicit AhoCorasick(const std::vector<std::string>& patterns);

    std::vector<Match> search(const std::string& text) const;

private:
    struct State {
        std::unordered_map<char, int> next;
        int fail = 0;
        std::vector<int> output;  // indices into patterns_
    };

    std::vector<State> automaton_;
    std::vector<std::string> patterns_;

    void build();
};

class PatternMatcher {
public:
    explicit PatternMatcher(const std::vector<std::string>& patterns);

    // Single text search
    std::vector<Match> search(const std::string& text) const;

    // Parallel search over multiple texts using std::thread
    std::vector<std::vector<Match>> search_parallel(const std::vector<std::string>& texts) const;

    int pattern_count() const;

private:
    AhoCorasick ac_;
    std::vector<std::string> patterns_;
};
