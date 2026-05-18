"""Patch Fetcher - downloads or generates patch files from various sources."""
import json
import os
import requests
from datetime import datetime
from typing import Optional, Dict


class PatchFetcher:
    """Fetch and save original patch files."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.patches_dir = os.path.join(workdir, cve_id, "patches")
        os.makedirs(self.patches_dir, exist_ok=True)

    def fetch_from_url(self, url: str, verify_ssl: bool = True) -> Dict:
        result = {
            "source_url": url,
            "success": False,
            "error": None,
            "path": None,
        }
        try:
            resp = requests.get(url, timeout=60, verify=verify_ssl)
            if resp.status_code == 200:
                path = os.path.join(self.patches_dir, "original.patch")
                with open(path, "wb") as f:
                    f.write(resp.content)
                result["success"] = True
                result["path"] = path
                result["size"] = len(resp.content)
            else:
                result["error"] = f"HTTP {resp.status_code}"
        except Exception as e:
            result["error"] = str(e)
        meta_path = os.path.join(self.patches_dir, "patch_source.json")
        with open(meta_path, "w") as f:
            json.dump(result, f, indent=2)
        return result

    def save_raw_patch(self, content: str, source_info: Dict) -> Dict:
        path = os.path.join(self.patches_dir, "original.patch")
        with open(path, "w") as f:
            f.write(content)
        result = {
            "source": source_info,
            "success": True,
            "path": path,
            "size": len(content),
        }
        meta_path = os.path.join(self.patches_dir, "patch_source.json")
        with open(meta_path, "w") as f:
            json.dump(result, f, indent=2)
        return result
