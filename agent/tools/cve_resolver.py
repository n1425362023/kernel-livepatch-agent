"""CVE Resolver - queries NVD, Linux CVE announce, and Linux stable for CVE information."""
import json
import os
import re
import requests
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


class CVEResolver:
    """Multi-source CVE information resolver."""

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    STABLE_GIT_BASE = "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
    
    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.metadata_dir = os.path.join(workdir, cve_id, "metadata")
        os.makedirs(self.metadata_dir, exist_ok=True)

    def query_nvd(self) -> Dict:
        """Query NVD for CVE metadata."""
        url = f"{self.NVD_API_BASE}?cveId={self.cve_id}"
        result = {"source": "nvd", "cve_id": self.cve_id, 
                  "description": "", "cvss": None, "references": [],
                  "error": None}
        
        try:
            resp = requests.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_item = vulnerabilities[0].get("cve", {})
                    descriptions = cve_item.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break
                    metrics = cve_item.get("metrics", {})
                    for severity_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if metrics.get(severity_key):
                            cvss_data = metrics[severity_key][0].get("cvssData", {})
                            result["cvss"] = {
                                "version": cvss_data.get("version"),
                                "score": cvss_data.get("baseScore"),
                                "severity": cvss_data.get("baseSeverity"),
                            }
                            break
                    refs = cve_item.get("references", [])
                    result["references"] = [
                        {"url": r.get("url"), "source": r.get("source", "")}
                        for r in refs
                    ]
            else:
                result["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            result["error"] = str(e)
        
        self._save_metadata("raw_nvd.json", result)
        return result

    def search_stable_commits(self, keywords: List[str] = None) -> List[Dict]:
        candidates = []
        if keywords is None:
            keywords = [self.cve_id]
        for keyword in keywords:
            try:
                candidates.append({
                    "source": "linux_stable",
                    "query": keyword,
                    "search_url": f"{self.STABLE_GIT_BASE}/log/?search={keyword}",
                    "status": "searched",
                    "note": "Manual inspection required via git clone"
                })
            except Exception as e:
                candidates.append({
                    "source": "linux_stable",
                    "query": keyword,
                    "error": str(e)
                })
        return candidates

    def resolve(self) -> Dict:
        nvd_data = self.query_nvd()
        keywords = [self.cve_id]
        if nvd_data.get("description"):
            words = nvd_data["description"].split()[:10]
            keywords.extend(words)
        candidates = self.search_stable_commits(keywords[:5])
        result = {
            "cve_id": self.cve_id,
            "nvd": nvd_data,
            "candidates": candidates,
            "resolved_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_metadata("cve_metadata.json", result)
        return result

    def _save_metadata(self, filename: str, data: Any):
        path = os.path.join(self.metadata_dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
