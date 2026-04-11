"""
NVD CVE ingestor.

Uses the NVD 2.0 REST API (the legacy JSON feeds were deprecated in 2023).
Fetches high/critical severity CVEs (CVSS >= 7.0) for 2020-2024 and ingests
them into ChromaDB.

Rate limit without API key: 5 requests / 30 seconds.
Set NVD_API_KEY in the environment to raise the limit to 50 / 30 seconds.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Optional

import requests

from rag.chroma_store import SecurityChromaStore
from rag.embedder import LocalEmbedder

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TARGET_YEARS = [2020, 2021, 2022, 2023, 2024]
MIN_CVSS = 7.0
MAX_PER_YEAR = 3000      # cap per year to stay near 10k total
RESULTS_PER_PAGE = 2000  # NVD API maximum
REQUEST_DELAY = 6.0      # seconds between requests (unauthenticated rate limit)


def _cvss_score(cve: dict) -> float:
    """Extract the highest available CVSS base score from a NVD 2.0 CVE object."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            return float(entries[0].get("cvssData", {}).get("baseScore", 0.0))
    return 0.0


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _cve_to_document(cve: dict) -> Optional[dict]:
    """Convert a NVD 2.0 CVE object to a document dict. Returns None if not useful."""
    cve_id = cve.get("id", "")

    # Description
    desc_list = cve.get("descriptions", [])
    description = " ".join(
        d.get("value", "") for d in desc_list if d.get("lang") == "en"
    )
    if len(description) < 50:
        return None

    score = _cvss_score(cve)
    severity = _severity_from_score(score)

    # CWE
    cwes: list[str] = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)

    # References
    ref_urls = [r.get("url", "") for r in cve.get("references", [])[:5]]

    # Platform detection from CPE data
    platform = "cross"
    cpe_str = ""
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe_str += " " + cpe_match.get("criteria", "").lower()
    if cpe_str:
        if "windows" in cpe_str and "linux" not in cpe_str:
            platform = "windows"
        elif "linux" in cpe_str and "windows" not in cpe_str:
            platform = "linux"
        elif "macos" in cpe_str or "mac_os" in cpe_str:
            platform = "macos"

    content = (
        f"CVE ID: {cve_id}\n"
        f"CVSS Score: {score} ({severity})\n"
        f"CWE: {', '.join(cwes) or 'N/A'}\n\n"
        f"Description:\n{description}\n\n"
        f"References:\n" + "\n".join(ref_urls)
    )

    return {
        "content": content,
        "metadata": {
            "source": "nvd",
            "cve_id": cve_id,
            "platform": platform,
            "severity": severity,
            "cvss_score": str(score),
            "cwe": ",".join(cwes),
            "tags": f"cve,{severity},{platform}",
            "technique_id": "",
        },
    }


class NVDIngestor:
    """
    Fetches CVEs from the NVD 2.0 REST API and ingests high-severity entries
    into ChromaDB.

    Usage:
        ingestor = NVDIngestor()
        n = ingestor.run(store, embedder)
    """

    def __init__(
        self,
        years: list[int] = None,
        min_cvss: float = MIN_CVSS,
        max_per_year: int = MAX_PER_YEAR,
        cache_dir: str = "data",
    ):
        self.years = years or TARGET_YEARS
        self.min_cvss = min_cvss
        self.max_per_year = max_per_year
        self.cache_dir = Path(cache_dir)
        self.api_key = os.environ.get("NVD_API_KEY")
        self._last_request = 0.0

    def _get(self, params: dict) -> dict:
        """Make a rate-limited GET request to the NVD API."""
        elapsed = time.monotonic() - self._last_request
        delay = REQUEST_DELAY if not self.api_key else 0.6
        if elapsed < delay:
            time.sleep(delay - elapsed)

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        # Build query string manually — requests encodes colons in timestamps
        # as %3A which NVD rejects with 404.
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        response = requests.get(f"{NVD_API_URL}?{qs}", headers=headers, timeout=60)
        self._last_request = time.monotonic()
        response.raise_for_status()
        return response.json()

    # NVD API enforces a 120-day maximum date range per request.
    # Split each year into quarters to stay well within the limit.
    _QUARTERS = [
        ("01-01", "03-31"),
        ("04-01", "06-30"),
        ("07-01", "09-30"),
        ("10-01", "12-31"),
    ]

    def _fetch_quarter(self, year: int, start: str, end: str) -> list[dict]:
        """Fetch one quarter's CVEs, paginating as needed."""
        cves: list[dict] = []
        start_index = 0
        total = None
        base_params = {
            "pubStartDate": f"{year}-{start}T00:00:00.000",
            "pubEndDate": f"{year}-{end}T23:59:59.999",
            "resultsPerPage": RESULTS_PER_PAGE,
        }
        while True:
            params = {**base_params, "startIndex": start_index}
            data = self._get(params)
            if total is None:
                total = data.get("totalResults", 0)
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                if _cvss_score(cve) >= self.min_cvss:
                    cves.append(cve)
            fetched = start_index + len(data.get("vulnerabilities", []))
            if fetched >= total:
                break
            start_index = fetched
        return cves

    def _fetch_year(self, year: int) -> list[dict]:
        """Fetch all high/critical CVEs for a given year from the NVD API."""
        cache_file = self.cache_dir / f"nvd-{year}.json"
        if cache_file.exists():
            with open(cache_file) as f:
                return json.load(f)

        print(f"  Fetching NVD {year} from API (4 quarters)...")
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        all_cves: list[dict] = []
        for start, end in self._QUARTERS:
            quarter_cves = self._fetch_quarter(year, start, end)
            all_cves.extend(quarter_cves)
            if len(all_cves) >= self.max_per_year:
                all_cves = all_cves[: self.max_per_year]
                break

        with open(cache_file, "w") as f:
            json.dump(all_cves, f)

        return all_cves

    def fetch_documents(self) -> list[dict]:
        """Fetch all years and return filtered document list."""
        all_docs: list[dict] = []
        for year in self.years:
            cves = self._fetch_year(year)
            year_docs: list[dict] = []
            for cve in cves:
                doc = _cve_to_document(cve)
                if doc:
                    year_docs.append(doc)
            print(f"  {year}: {len(year_docs)} high-severity CVEs")
            all_docs.extend(year_docs)

        print(f"Total CVE documents: {len(all_docs)}")
        return all_docs

    def run(
        self,
        store: SecurityChromaStore,
        embedder: Optional[LocalEmbedder] = None,
    ) -> int:
        docs = self.fetch_documents()
        print(f"Ingesting {len(docs)} CVE documents into ChromaDB...")
        n = store.add_documents(docs, embedder)
        print(f"Done — {n} chunks upserted")
        return n
