"""
Tests for the C++ security_cpp extension.

Run: python tests/test_cpp.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import security_cpp
    print("security_cpp extension loaded successfully")
except ImportError as e:
    print(f"Extension not built yet: {e}")
    print("Build with: cd cpp_extensions && pip install -e .")
    sys.exit(0)


def test_mitre_graph():
    print("\n--- MITREGraph Tests ---")
    g = security_cpp.MITREGraph()

    # Add some techniques
    g.add_technique("T1566.001", "Spearphishing Attachment", "initial-access",
                    ["windows", "macos", "linux"], [], 0.7)
    g.add_technique("T1059.001", "PowerShell", "execution",
                    ["windows"], [], 0.4)
    g.add_technique("T1059.004", "Unix Shell", "execution",
                    ["linux", "macos"], [], 0.5)
    g.add_technique("T1078", "Valid Accounts", "persistence",
                    ["windows", "linux", "macos"], [], 0.8)
    g.add_technique("T1003", "OS Credential Dumping", "credential-access",
                    ["windows", "linux", "macos"], [], 0.3)
    g.add_technique("T1083", "File Discovery", "discovery",
                    ["windows", "linux", "macos"], [], 0.6)
    g.add_technique("T1020", "Automated Exfiltration", "exfiltration",
                    ["windows", "linux", "macos"], [], 0.4)

    print(f"  Nodes: {g.node_count()}, Edges before default: {g.edge_count()}")
    g.build_default_edges()
    print(f"  Nodes: {g.node_count()}, Edges after default: {g.edge_count()}")

    # A* search
    result = g.astar("T1566.001", "exfiltration")
    print(f"  A* (initial-access → exfiltration): {result}")
    assert result.found, "A* should find a path"

    # Platform-filtered search
    result_win = g.astar("T1566.001", "exfiltration", platform_filter="windows")
    print(f"  A* (windows filter): {result_win}")

    # Shortest path
    sp = g.shortest_path("T1566.001", "T1020")
    print(f"  Dijkstra (T1566.001 → T1020): {sp}")

    # Queries
    exec_techniques = g.techniques_by_tactic("execution")
    print(f"  Execution techniques: {exec_techniques}")

    linux_techniques = g.techniques_by_platform("linux")
    print(f"  Linux techniques: {linux_techniques}")

    print("  MITREGraph tests PASSED")


def test_pattern_matcher():
    print("\n--- PatternMatcher Tests ---")
    patterns = ["lsass", "mimikatz", "credential", "/etc/shadow", "powershell"]
    pm = security_cpp.PatternMatcher(patterns)
    print(f"  PatternMatcher: {pm}")

    # Single text search
    text = "Attacker ran mimikatz to dump credential hashes from lsass memory"
    matches = pm.search(text)
    print(f"  Matches in '{text[:50]}...':")
    for m in matches:
        print(f"    {m}")
    assert len(matches) >= 3, f"Expected at least 3 matches, got {len(matches)}"

    # Parallel search
    texts = [
        "Running powershell with encoded command",
        "cat /etc/shadow to extract hashes",
        "Normal log entry: HTTP 200 OK",
        "mimikatz sekurlsa::logonpasswords",
    ]
    results = pm.search_parallel(texts)
    print(f"  Parallel search over {len(texts)} texts:")
    for i, (t, res) in enumerate(zip(texts, results)):
        print(f"    [{i}] '{t[:40]}': {len(res)} match(es)")

    assert len(results[2]) == 0, "Benign text should have no matches"
    assert len(results[3]) >= 1, "mimikatz text should have matches"

    print("  PatternMatcher tests PASSED")


if __name__ == "__main__":
    test_mitre_graph()
    test_pattern_matcher()
    print("\nAll C++ extension tests PASSED")
