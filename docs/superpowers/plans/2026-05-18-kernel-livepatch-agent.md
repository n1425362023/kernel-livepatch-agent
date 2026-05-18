# Kernel CVE Livepatch Auto-Generation Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a working CLI agent that takes CVE IDs and outputs livepatch `.ko` modules with structured reports, following the architecture in `v1.md`.

**Architecture:** Python-based Agent with Planner, Tool Router, State Manager, and pluggable tools for CVE retrieval, patch handling, kpatch-build integration, failure classification, rewrite advisor, verifier, and reporter.

**Tech Stack:** Python 3.6+, git, kpatch-build, Linux kernel livepatch tools, Docker (for build containers), pytest

**Base path:** `/tmp/opencode/kernel-livepatch-agent/`

---

### Task 1: Project Infrastructure & CLI Entry Point

**Files:**
- Create: `setup.py` - Package setup
- Create: `requirements.txt` - Dependencies
- Create: `run` - CLI entry point (executable)
- Create: `agent/state.py` - State manager (state.json, run_config.json)
- Create: `agent/planner.py` - Planner (state machine & orchestration)
- Create: `agent/__main__.py` - Module entry point

- [ ] **Step 1: Write setup.py**

```python
from setuptools import setup, find_packages

setup(
    name="kernel-livepatch-agent",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests>=2.25.0",
        "pyyaml>=5.0",
    ],
    entry_points={
        "console_scripts": [
            "run=agent.__main__:main",
        ],
    },
    python_requires=">=3.6",
)
```

- [ ] **Step 2: Write requirements.txt**

```
requests>=2.25.0
pyyaml>=5.0
```

- [ ] **Step 3: Write agent/state.py**

State manager implementing `state.json` per CVE, `run_config.json` for batch runs. Must handle:
- Create task directory with `state.json`
- Load/save state with transitions
- Track attempt count
- Record environment info

```python
"""State Manager - maintains state.json and run_config.json per v1.md design."""
import json
import os
import datetime
from typing import Optional, Dict, Any, List


VALID_STATES = [
    "TaskCreated", "CveResolved", "PatchFetched", "PatchAnalyzed",
    "TargetChecked", "PatchApplied", "BuildRunning", "BuildSucceeded",
    "BuildFailed", "FailureClassified", "RewritePrepared", "ManualRequired",
    "Failed", "LoadTesting", "Verified", "VerifyFailed", "ReportWritten"
]

VALID_FINAL_STATUSES = ["success", "failed", "manual_required", "skipped"]


class StateManager:
    """Manages per-CVE state and batch run configuration."""

    def __init__(self, workdir: str):
        self.workdir = workdir
        self.run_config_path = os.path.join(workdir, "run_config.json")

    # --- Batch-level config ---

    def init_run_config(self, cve_ids: List[str], kernel_version: str,
                        max_attempts: int = 5) -> Dict:
        config = {
            "created_at": datetime.datetime.utcnow().isoformat(),
            "kernel_version": kernel_version,
            "max_attempts": max_attempts,
            "cve_count": len(cve_ids),
            "cve_ids": cve_ids,
        }
        self._write_json(self.run_config_path, config)
        return config

    def get_run_config(self) -> Dict:
        return self._read_json(self.run_config_path)

    # --- Per-CVE state ---

    def init_cve_state(self, cve_id: str) -> Dict:
        cve_dir = os.path.join(self.workdir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        state = {
            "cve_id": cve_id,
            "state": "TaskCreated",
            "attempt": 0,
            "max_attempts": self.get_run_config().get("max_attempts", 5),
            "status": None,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "updated_at": datetime.datetime.utcnow().isoformat(),
            "last_error": None,
            "evidence_paths": {},
        }
        self._write_json(os.path.join(cve_dir, "state.json"), state)
        return state

    def get_state(self, cve_id: str) -> Dict:
        return self._read_json(os.path.join(self.workdir, cve_id, "state.json"))

    def transition_to(self, cve_id: str, new_state: str,
                      reason: str = "", evidence: Optional[Dict] = None):
        state = self.get_state(cve_id)
        assert new_state in VALID_STATES, f"Invalid state: {new_state}"
        old_state = state["state"]
        state["state"] = new_state
        state["updated_at"] = datetime.datetime.utcnow().isoformat()
        if evidence:
            state["evidence_paths"].update(evidence)
        # Record transition
        transition = {
            "from": old_state,
            "to": new_state,
            "reason": reason,
            "timestamp": state["updated_at"],
        }
        events = self._read_json(
            os.path.join(self.workdir, cve_id, "events.jsonl"), default=[])
        events.append(transition)
        self._write_json(
            os.path.join(self.workdir, cve_id, "events.jsonl"), events)
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)
        return state

    def increment_attempt(self, cve_id: str) -> int:
        state = self.get_state(cve_id)
        state["attempt"] += 1
        state["updated_at"] = datetime.datetime.utcnow().isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)
        return state["attempt"]

    def set_final_status(self, cve_id: str, status: str):
        assert status in VALID_FINAL_STATUSES, f"Invalid final status: {status}"
        state = self.get_state(cve_id)
        state["status"] = status
        state["updated_at"] = datetime.datetime.utcnow().isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)

    def set_error(self, cve_id: str, error: str):
        state = self.get_state(cve_id)
        state["last_error"] = error
        state["updated_at"] = datetime.datetime.utcnow().isoformat()
        self._write_json(os.path.join(self.workdir, cve_id, "state.json"), state)

    # --- Helpers ---

    def cve_dir(self, cve_id: str) -> str:
        return os.path.join(self.workdir, cve_id)

    def ensure_subdir(self, cve_id: str, subdir: str) -> str:
        path = os.path.join(self.workdir, cve_id, subdir)
        os.makedirs(path, exist_ok=True)
        return path

    # --- Internal ---

    @staticmethod
    def _write_json(path: str, data: Any):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _read_json(path: str, default=None) -> Any:
        if not os.path.exists(path):
            return default if default is not None else {}
        with open(path) as f:
            return json.load(f)
```

- [ ] **Step 4: Write agent/planner.py**

Planner reads state and decides next action. Implements the state machine from v1.md section 3.6.

```python
"""Planner - decides next action based on CVE state machine."""
import os
from typing import List, Optional, Dict, Any
from agent.state import StateManager, VALID_FINAL_STATUSES


class Planner:
    """Determines next action for each CVE based on its current state."""

    def __init__(self, state_mgr: StateManager):
        self.state_mgr = state_mgr

    def decide_next(self, cve_id: str) -> Dict[str, Any]:
        """Read current state and decide next action."""
        state = self.state_mgr.get_state(cve_id)
        current = state.get("state", "TaskCreated")
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)

        if state.get("status") in VALID_FINAL_STATUSES:
            return {"action": "done", "reason": "Already in final state"}

        transitions = {
            "TaskCreated": {"action": "resolve_cve", "next_state": "CveResolved"},
            "CveResolved": {"action": "fetch_patch", "next_state": "PatchFetched"},
            "PatchFetched": {"action": "analyze_patch", "next_state": "PatchAnalyzed"},
            "PatchAnalyzed": {"action": "check_target", "next_state": "TargetChecked"},
            "TargetChecked": {"action": "apply_patch", "next_state": "PatchApplied"},
            "PatchApplied": {"action": "run_build", "next_state": "BuildRunning"},
            "BuildRunning": {"action": "check_build_result", "next_state": None},
            "BuildSucceeded": {"action": "run_verify", "next_state": "LoadTesting"},
            "BuildFailed": {"action": "classify_failure", "next_state": "FailureClassified"},
            "FailureClassified": self._decide_after_classification,
            "RewritePrepared": {"action": "apply_patch", "next_state": "PatchApplied"},
            "LoadTesting": {"action": "check_verify_result", "next_state": None},
            "VerifyFailed": {"action": "classify_verify_failure", "next_state": "FailureClassified"},
            "Verified": {"action": "write_report", "next_state": "ReportWritten"},
            "ManualRequired": {"action": "done", "next_state": None,
                               "reason": "Manual intervention required"},
            "Failed": {"action": "done", "next_state": None,
                       "reason": "Max attempts reached or unrecoverable"},
        }

        if current in transitions:
            decision = transitions[current]
            if callable(decision):
                return decision(state)
            if decision.get("next_state") is None:
                return {"action": decision["action"], 
                        "next_state": decision.get("next_state"),
                        "reason": decision.get("reason", "")}
            return {"action": decision["action"],
                    "next_state": decision["next_state"]}

        return {"action": "unknown", "reason": f"Unknown state: {current}"}

    def _decide_after_classification(self, state: Dict) -> Dict:
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)
        # Check if retryable and under limit
        if attempt < max_attempts:
            return {"action": "prepare_rewrite", "next_state": "RewritePrepared"}
        else:
            return {"action": "done", "next_state": "Failed",
                    "reason": f"Max attempts ({max_attempts}) reached"}

    def get_all_cve_dirs(self) -> List[str]:
        """Get all CVE directories in workdir."""
        items = os.listdir(self.state_mgr.workdir)
        return [d for d in items if d.startswith("CVE-")
                and os.path.isdir(os.path.join(self.state_mgr.workdir, d))]

    def get_active_cves(self) -> List[str]:
        """Get CVE IDs that are not in final state."""
        active = []
        for cve_id in self.get_all_cve_dirs():
            state = self.state_mgr.get_state(cve_id)
            if state.get("status") not in VALID_FINAL_STATUSES:
                active.append(cve_id)
        return active
```

- [ ] **Step 5: Write agent/__main__.py**

CLI entry point with argument parsing per v1.md section 3.10.

```python
#!/usr/bin/env python3
"""CLI entry point for Kernel CVE Livepatch Auto-Generation Agent."""
import argparse
import os
import sys
import json
import datetime

from agent.state import StateManager
from agent.planner import Planner


def validate_cve_id(cve_id: str) -> bool:
    """Validate CVE ID format: CVE-YYYY-NNNNNNNN or CVE-YYYY-NNNN."""
    import re
    return bool(re.match(r'^CVE-\d{4}-\d{4,}$', cve_id))


def parse_cves_file(path: str) -> list:
    """Parse cves.txt, return list of valid CVE IDs with duplicates recorded."""
    if not os.path.exists(path):
        print(f"Error: CVEs file not found: {path}", file=sys.stderr)
        sys.exit(1)
    
    valid = []
    invalid = []
    seen = set()
    
    with open(path) as f:
        for line in f:
            cve_id = line.strip()
            if not cve_id:
                continue
            if not validate_cve_id(cve_id):
                invalid.append(cve_id)
            elif cve_id in seen:
                print(f"Warning: Duplicate CVE skipped: {cve_id}")
            else:
                valid.append(cve_id)
                seen.add(cve_id)
    
    if invalid:
        print(f"Warning: Invalid CVE IDs skipped: {invalid}", file=sys.stderr)
    
    return valid


def main():
    parser = argparse.ArgumentParser(
        description="Kernel CVE Livepatch Auto-Generation Agent")
    parser.add_argument("--cves", required=True,
                        help="Path to cves.txt (one CVE ID per line)")
    parser.add_argument("--kernel-version",
                        default="6.6.102-5.2.an23.x86_64",
                        help="Target kernel version")
    parser.add_argument("--workdir", default=None,
                        help="Output working directory (default: auto-create)")
    parser.add_argument("--max-attempts", type=int, default=5,
                        help="Max rewrite attempts per CVE (default: 5)")
    
    args = parser.parse_args()
    
    # Parse CVE list
    cve_ids = parse_cves_file(args.cves)
    if not cve_ids:
        print("Error: No valid CVE IDs found.", file=sys.stderr)
        sys.exit(1)
    
    print(f"Loaded {len(cve_ids)} CVE(s): {', '.join(cve_ids)}")
    
    # Setup workdir
    if args.workdir:
        workdir = args.workdir
    else:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        workdir = os.path.join(os.getcwd(), f"run_{timestamp}")
    
    os.makedirs(workdir, exist_ok=True)
    print(f"Working directory: {workdir}")
    
    # Initialize state manager and planner
    state_mgr = StateManager(workdir)
    state_mgr.init_run_config(cve_ids, args.kernel_version, args.max_attempts)
    
    planner = Planner(state_mgr)
    
    # Initialize each CVE
    for cve_id in cve_ids:
        state_mgr.init_cve_state(cve_id)
        print(f"  Initialized: {cve_id}")
    
    # Save run config
    run_config = state_mgr.get_run_config()
    print(f"\nRun configuration saved.")
    print(f"  Kernel version: {run_config['kernel_version']}")
    print(f"  Max attempts per CVE: {run_config['max_attempts']}")
    print(f"\nAgent initialized. Ready to process {len(cve_ids)} CVE(s).")
    
    # Print next steps
    for cve_id in cve_ids:
        decision = planner.decide_next(cve_id)
        print(f"  {cve_id}: next action = {decision['action']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 6: Make run executable and test import**

Run: `python3 -c "from agent.state import StateManager; print('OK')"`

- [ ] **Step 7: Create a sample cves.txt**

```
# Sample CVE list for testing
CVE-2026-0001
CVE-2026-0002
```

- [ ] **Step 8: Test the CLI**

Run: `python3 /tmp/opencode/kernel-livepatch-agent/run --cves /tmp/opencode/kernel-livepatch-agent/sample_cves.txt --workdir /tmp/opencode/kernel-livepatch-agent/test_run`

Expected: Creates working directory, initializes state for each CVE, prints next actions.

---

### Task 2: CVE Retrieval Tools

**Files:**
- Create: `agent/tools/cve_resolver.py` - NVD + Linux CVE announce + Linux stable search

- [ ] **Step 1: Write agent/tools/cve_resolver.py**

```python
"""CVE Resolver - queries NVD, Linux CVE announce, and Linux stable for CVE information."""
import json
import os
import re
import requests
from datetime import datetime
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
                    # Extract description
                    descriptions = cve_item.get("descriptions", [])
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            result["description"] = desc.get("value", "")
                            break
                    # Extract CVSS
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
                    # Extract references
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
        """Search Linux stable repository for candidate commits."""
        # Use public git log search via remote
        candidates = []
        
        if keywords is None:
            keywords = [self.cve_id]
        
        # Try direct CVE ID search in commit messages
        for keyword in keywords:
            search_url = (f"{self.STABLE_GIT_BASE}"
                         f"/plain/?search={keyword}")
            try:
                resp = requests.get(
                    f"{self.STABLE_GIT_BASE}/log/?search={keyword}",
                    timeout=30, headers={"Accept": "text/plain"}
                )
                # For now, return structured candidate with search info
                candidates.append({
                    "source": "linux_stable",
                    "query": keyword,
                    "search_url": search_url,
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
        """Run full CVE resolution pipeline."""
        nvd_data = self.query_nvd()
        
        # Extract keywords from NVD for stable search
        keywords = [self.cve_id]
        if nvd_data.get("description"):
            # Extract subsystem hints from description
            words = nvd_data["description"].split()[:10]
            keywords.extend(words)
        
        candidates = self.search_stable_commits(keywords[:5])
        
        result = {
            "cve_id": self.cve_id,
            "nvd": nvd_data,
            "candidates": candidates,
            "resolved_at": datetime.utcnow().isoformat(),
        }
        
        self._save_metadata("cve_metadata.json", result)
        return result

    def _save_metadata(self, filename: str, data: Any):
        path = os.path.join(self.metadata_dir, filename)
        with open(path, "w") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
```

- [ ] **Step 2: Test import**

Run: `python3 -c "from agent.tools.cve_resolver import CVEResolver; print('OK')"`

---

### Task 3: Patch Handling Tools

**Files:**
- Create: `agent/tools/patch_fetcher.py` - Download patches from URLs or generate
- Create: `agent/tools/patch_parser.py` - Parse unified diff into patch_ir.json + change_units.json

- [ ] **Step 1: Write agent/tools/patch_fetcher.py**

```python
"""Patch Fetcher - downloads or generates patch files from various sources."""
import json
import os
import re
import requests
from datetime import datetime
from typing import Optional, Dict, List


class PatchFetcher:
    """Fetch and save original patch files."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.patches_dir = os.path.join(workdir, cve_id, "patches")
        os.makedirs(self.patches_dir, exist_ok=True)

    def fetch_from_url(self, url: str, verify_ssl: bool = True) -> Dict:
        """Download patch from URL and save as original.patch."""
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
        
        # Save metadata
        meta_path = os.path.join(self.patches_dir, "patch_source.json")
        with open(meta_path, "w") as f:
            json.dump(result, f, indent=2)
        
        return result

    def save_raw_patch(self, content: str, source_info: Dict) -> Dict:
        """Save raw patch content as original.patch with metadata."""
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
```

- [ ] **Step 2: Write agent/tools/patch_parser.py**

```python
"""Patch Parser - parses unified diff into structured patch_ir.json and change_units.json."""
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class PatchParser:
    """Parse unified diff files into structured intermediate representation."""

    # Risk detection patterns
    INIT_PATTERN = re.compile(r'\b__init\b')
    STATIC_PATTERN = re.compile(r'\bstatic\s+(struct|int|char|bool|long|unsigned|void\s*\*)\s+\w+\s*[=;]')
    GLOBAL_PATTERN = re.compile(r'^(?!static)\s*(struct|int|char|bool|long|unsigned|void\s*\*)\s+\w+\s*[=;]', re.MULTILINE)
    NO_FENTRY_PATTERN = re.compile(r'(no fentry|not traceable|FTRACE_NOT_AVAILABLE)')
    STRUCT_PATTERN = re.compile(r'^diff.*struct\s+\w+', re.MULTILINE)

    SEMANTIC_ROLE_PATTERNS = {
        "security_boundary_check": [r'\bif\s*\(.*len\s*[><=]', r'\bif\s*\(.*size\s*[><=]',
                                     r'\bif\s*\(.*ptr\s*==\s*NULL', r'\bif\s*\(!.*ptr\b',
                                     r'return\s*-?E(Access|INVAL|FAULT|PERM)'],
        "permission_check": [r'capable\(', r'ns_capable\(', r'permitted\('],
        "refcount_lifetime": [r'\bkref_get\b', r'\bkref_put\b', r'\bget_device\b', r'\bput_device\b',
                              r'\bmodule_get\b', r'\bmodule_put\b'],
        "locking_order": [r'\bmutex_lock\b', r'\bmutex_unlock\b', r'\bspin_lock\b', r'\bspin_unlock\b',
                          r'\bdown_read\b', r'\bup_read\b'],
        "init_path_change": [r'__init\b', r'__exit\b', r'late_initcall', r'early_initcall'],
        "logging_only": [r'^\s*[+-]\s*(printk|pr_err|pr_info|pr_warn|pr_debug|dev_err|dev_info)\('],
    }

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def parse_patch(self, patch_path: str) -> Dict:
        """Parse a unified diff file into patch_ir.json."""
        with open(patch_path) as f:
            content = f.read()

        files = self._parse_files(content)
        functions = self._extract_functions(content, files)
        risk_tags = self._detect_risks(content, functions)
        semantic_summary = self._generate_semantic_summary(content)

        patch_ir = {
            "cve_id": self.cve_id,
            "parsed_at": datetime.utcnow().isoformat(),
            "files": files,
            "functions": functions,
            "risk_tags": list(set(risk_tags)),
            "target_status": "need_backport",
            "semantic_summary": semantic_summary,
        }

        # Generate change units
        change_units = self._generate_change_units(patch_ir)

        # Save both outputs
        cve_dir = os.path.join(self.workdir, self.cve_id)
        with open(os.path.join(cve_dir, "patch_ir.json"), "w") as f:
            json.dump(patch_ir, f, indent=2, ensure_ascii=False)
        with open(os.path.join(cve_dir, "change_units.json"), "w") as f:
            json.dump(change_units, f, indent=2, ensure_ascii=False)

        return patch_ir

    def _parse_files(self, content: str) -> List[Dict]:
        """Extract file information from diff headers."""
        files = []
        for match in re.finditer(r'^diff --git a/(.*?) b/(.*?)$', content, re.MULTILINE):
            hunk_count = len(re.findall(
                rf'^@@.*{re.escape(match.group(1))}.*@@', content, re.MULTILINE))
            files.append({
                "path": match.group(2),
                "status": "modified",
                "hunk_count": max(hunk_count, 1),
            })
        return files

    def _extract_functions(self, content: str, files: List[Dict]) -> List[Dict]:
        """Extract affected function names from hunk headers and context."""
        functions = []
        seen = set()

        # Check hunk headers for function context
        for match in re.finditer(r'@@.*@@\s*(.*?)(?=\n[+-])', content):
            func_hint = match.group(1).strip()
            # Extract function name from hunk header context
            func_match = re.search(r'(\w+)\s*\(', func_hint)
            if func_match and func_match.group(1) not in seen:
                seen.add(func_match.group(1))
                functions.append({
                    "name": func_match.group(1),
                    "file": files[0]["path"] if files else "unknown",
                    "risk_tags": self._function_risk_tags(content, func_match.group(1)),
                })

        return functions

    def _function_risk_tags(self, content: str, func_name: str) -> List[str]:
        """Detect risk tags for a specific function."""
        tags = []
        # Find function context in diff
        func_region = re.search(
            rf'[+-].*{re.escape(func_name)}.*(?:\n[+-].*)*', content)
        if func_region:
            region = func_region.group()
            if self.INIT_PATTERN.search(region):
                tags.append("init_function")
            if self.STATIC_PATTERN.search(region):
                tags.append("static_data")
            if self.GLOBAL_PATTERN.search(region):
                tags.append("global_data")
        return tags

    def _detect_risks(self, content: str, functions: List[Dict]) -> List[str]:
        """Detect kpatch risk patterns across the entire patch."""
        risks = []

        for func in functions:
            risks.extend(func.get("risk_tags", []))

        if self.STRUCT_PATTERN.search(content):
            risks.append("struct_abi")
        if self.NO_FENTRY_PATTERN.search(content):
            risks.append("no_fentry")

        return risks

    def _generate_semantic_summary(self, content: str) -> str:
        """Generate a short semantic summary of the patch."""
        added_lines = re.findall(r'^\+(?!\+\+)', content, re.MULTILINE)
        removed_lines = re.findall(r'^-(?!--)', content, re.MULTILINE)

        parts = []
        if any(self.SEMANTIC_ROLE_PATTERNS["security_boundary_check"].search(l) for l in added_lines):
            parts.append("add security boundary check")
        if any(self.SEMANTIC_ROLE_PATTERNS["permission_check"].search(l) for l in added_lines):
            parts.append("add permission check")
        if any(self.SEMANTIC_ROLE_PATTERNS["refcount_lifetime"].search(l) for l in added_lines):
            parts.append("modify reference counting")
        if any(self.SEMANTIC_ROLE_PATTERNS["locking_order"].search(l) for l in added_lines):
            parts.append("modify locking")
        if any(self.SEMANTIC_ROLE_PATTERNS["init_path_change"].search(l) for l in added_lines + removed_lines):
            parts.append("modify initialization path")

        return "; ".join(parts) if parts else "general bug fix"

    def _generate_change_units(self, patch_ir: Dict) -> Dict:
        """Generate change_units.json from patch_ir."""
        units = []
        for idx, func in enumerate(patch_ir.get("functions", [])):
            change_id = f"CU-{idx+1:03d}"

            # Determine semantic role
            role = self._classify_semantic_role(func.get("name", ""), patch_ir)

            # Determine if rewrite allowed
            risk_tags = func.get("risk_tags", [])
            rewrite_allowed = not any(t in risk_tags for t in 
                                       ["init_function", "global_data", "struct_abi"])

            unit = {
                "change_id": change_id,
                "file": func.get("file", "unknown"),
                "function": func.get("name", "unknown"),
                "change_type": "modify",
                "semantic_role": role,
                "risk_tags": risk_tags + patch_ir.get("risk_tags", []),
                "rewrite_allowed": rewrite_allowed,
                "target_context": {
                    "status": "need_backport",
                    "target_function_exists": True,
                    "signature_changed": False,
                    "context_similarity": 0.8,
                }
            }
            units.append(unit)

        return {
            "cve_id": self.cve_id,
            "kernel_version": "6.6.102-5.2.an23.x86_64",
            "fix_intent": {
                "summary": patch_ir.get("semantic_summary", ""),
                "source": "patch_analysis",
                "confidence": 0.8,
            },
            "units": units,
        }

    def _classify_semantic_role(self, func_name: str, patch_ir: Dict) -> str:
        """Classify the semantic role of a change."""
        risk_tags = []
        for f in patch_ir.get("functions", []):
            risk_tags.extend(f.get("risk_tags", []))
        risk_tags.extend(patch_ir.get("risk_tags", []))

        if "struct_abi" in risk_tags:
            return "struct_abi_change"
        if "init_function" in risk_tags:
            return "init_path_change"
        if "security_boundary_check" in patch_ir.get("semantic_summary", ""):
            return "security_boundary_check"
        if "locking" in patch_ir.get("semantic_summary", ""):
            return "locking_order"
        if "reference counting" in patch_ir.get("semantic_summary", ""):
            return "refcount_lifetime"

        return "security_boundary_check"  # default for CVE fixes
```

- [ ] **Step 3: Test imports**

Run: `python3 -c "from agent.tools.patch_fetcher import PatchFetcher; from agent.tools.patch_parser import PatchParser; print('OK')"`

---

### Task 4: kpatch-build Integration & Failure Classification

**Files:**
- Create: `agent/tools/kpatch_builder.py` - Execute kpatch-build, capture logs
- Create: `agent/tools/failure_classifier.py` - Classify build failures

- [ ] **Step 1: Write agent/tools/kpatch_builder.py**

```python
"""kpatch-build integration - execute builds and capture results."""
import json
import os
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, Optional, List


class KpatchBuilder:
    """Wrapper around kpatch-build tool."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.logs_dir = os.path.join(workdir, cve_id, "logs")
        self.artifacts_dir = os.path.join(workdir, cve_id, "artifacts")
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.artifacts_dir, exist_ok=True)

    def build(self, patch_path: str, source_dir: str, vmlinux_path: str,
              kernel_source_rpm: Optional[str] = None,
              kernel_devel_path: Optional[str] = None,
              attempt: int = 1) -> Dict:
        """Execute kpatch-build and return structured result."""
        log_path = os.path.join(self.logs_dir, f"build_{attempt}.log")
        result = {
            "attempt": attempt,
            "input_patch": patch_path,
            "source_dir": source_dir,
            "vmlinux": vmlinux_path,
            "return_code": -1,
            "success": False,
            "artifact_path": None,
            "sha256": None,
            "log_path": log_path,
            "error": None,
            "started_at": datetime.utcnow().isoformat(),
        }

        # Build command
        cmd = [
            "kpatch-build",
            "-s", source_dir,
            "-v", vmlinux_path,
            patch_path,
        ]

        if kernel_devel_path:
            cmd.extend(["-d", kernel_devel_path])

        # Execute
        try:
            with open(log_path, "w") as log_file:
                proc = subprocess.run(
                    cmd,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    timeout=1800,  # 30 minutes
                )
            result["return_code"] = proc.returncode
            result["success"] = proc.returncode == 0

            if proc.returncode == 0:
                # Find generated .ko
                ko_path = self._find_ko(source_dir)
                if ko_path:
                    result["artifact_path"] = ko_path
                    result["sha256"] = self._hash_file(ko_path)
                    # Copy to artifacts
                    import shutil
                    dest = os.path.join(self.artifacts_dir, "livepatch.ko")
                    shutil.copy2(ko_path, dest)
                    result["artifact_path"] = dest
                    # Generate sha256 file
                    with open(os.path.join(self.artifacts_dir, "livepatch.ko.sha256"), "w") as f:
                        f.write(f"{result['sha256']}  livepatch.ko\n")
        except subprocess.TimeoutExpired:
            result["error"] = "Build timed out after 30 minutes"
        except FileNotFoundError:
            result["error"] = "kpatch-build not found in PATH"
        except Exception as e:
            result["error"] = str(e)

        result["finished_at"] = datetime.utcnow().isoformat()

        # Save tool result
        tool_result_path = os.path.join(
            self.logs_dir, f"build_result_{attempt}.json")
        with open(tool_result_path, "w") as f:
            json.dump(result, f, indent=2)

        return result

    def check_environment(self) -> Dict:
        """Check if kpatch-build and required tools are available."""
        env_check = {
            "kpatch_build": False,
            "gcc": False,
            "make": False,
            "vmlinux_exists": False,
        }

        for cmd in ["kpatch-build", "gcc", "make"]:
            try:
                subprocess.run(
                    [cmd, "--version"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                )
                env_check[cmd.replace("-", "_")] = True
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        return env_check

    def _find_ko(self, source_dir: str) -> Optional[str]:
        """Find the generated .ko file."""
        for root, dirs, files in os.walk(source_dir):
            for f in files:
                if f.endswith(".ko") and "livepatch" in f:
                    return os.path.join(root, f)
        return None

    @staticmethod
    def _hash_file(path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
```

- [ ] **Step 2: Write agent/tools/failure_classifier.py**

Implements failure classification per v1.md sections 4.8 and rule table from 4.8.1.

```python
"""Failure Classifier - classifies build failures from logs into structured categories."""
import json
import os
import re
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class FailureClassifier:
    """Classify kpatch-build failures from build logs."""

    # Failure pattern definitions (from v1.md section 4.8.1)
    FAILURE_PATTERNS = [
        {
            "pattern_id": "apply.hunk_failed",
            "stage": "apply",
            "category": "patch_apply",
            "reason_code": "hunk_failed",
            "matchers": [
                r"hunk FAILED",
                r"patch does not apply",
                r"fuzz\s+\d+",
                r"error: patch failed",
            ],
            "retryable": True,
            "next_action": "rewrite",
        },
        {
            "pattern_id": "apply.file_missing",
            "stage": "apply",
            "category": "patch_apply",
            "reason_code": "file_missing",
            "matchers": [
                r"No such file or directory",
                r"cannot find file",
            ],
            "retryable": False,
            "next_action": "manual_required",
        },
        {
            "pattern_id": "compile.api_args",
            "stage": "build",
            "category": "compile",
            "reason_code": "api_mismatch",
            "matchers": [
                r"too many arguments to function",
                r"too few arguments to function",
                r"error: passing argument",
            ],
            "retryable": True,
            "next_action": "rewrite",
        },
        {
            "pattern_id": "compile.implicit_decl",
            "stage": "build",
            "category": "compile",
            "reason_code": "missing_api_or_include",
            "matchers": [
                r"implicit declaration of function",
                r"error: implicit declaration",
            ],
            "retryable": True,
            "next_action": "rewrite",
        },
        {
            "pattern_id": "compile.unknown_field",
            "stage": "build",
            "category": "compile",
            "reason_code": "field_mismatch",
            "matchers": [
                r"has no member named",
                r"error: \w+ has no member",
            ],
            "retryable": False,
            "next_action": "manual_required",
        },
        {
            "pattern_id": "kpatch.no_fentry",
            "stage": "build",
            "category": "kpatch_limit",
            "reason_code": "no_fentry",
            "matchers": [
                r"no fentry call",
                r"function is not traceable",
                r"fentry:",
            ],
            "retryable": False,
            "next_action": "manual_required",
        },
        {
            "pattern_id": "kpatch.data_change",
            "stage": "build",
            "category": "kpatch_limit",
            "reason_code": "struct_or_data_change",
            "matchers": [
                r"data structure layout change",
                r"static variable changed",
                r"unreconcilable difference",
                r"section change",
            ],
            "retryable": False,
            "next_action": "manual_required",
        },
        {
            "pattern_id": "env.no_vmlinux",
            "stage": "env_check",
            "category": "env_missing",
            "reason_code": "missing_vmlinux",
            "matchers": [
                r"vmlinux not found",
                r"cannot find vmlinux",
                r"ERROR:.*vmlinux",
            ],
            "retryable": False,
            "next_action": "fix_environment",
        },
        {
            "pattern_id": "compile.undefined_symbol",
            "stage": "build",
            "category": "compile",
            "reason_code": "undefined_symbol",
            "matchers": [
                r"undefined reference",
                r"undefined symbol",
                r"error:.*undefined",
            ],
            "retryable": True,
            "next_action": "rewrite",
        },
    ]

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def classify(self, build_log_path: str, attempt: int = 1) -> Dict:
        """Classify build failure from log file."""
        if not os.path.exists(build_log_path):
            return {
                "stage": "unknown",
                "category": "unknown",
                "reason_code": "log_not_found",
                "retryable": False,
                "next_action": "manual_required",
                "error": f"Build log not found: {build_log_path}"
            }

        with open(build_log_path) as f:
            log_content = f.read()

        # Try to match each failure pattern
        for pattern in self.FAILURE_PATTERNS:
            for matcher in pattern["matchers"]:
                match = re.search(matcher, log_content, re.IGNORECASE)
                if match:
                    # Extract location info
                    location = self._extract_location(log_content, match)
                    signals = [{
                        "pattern": matcher,
                        "signal": match.group(0),
                        "source": build_log_path,
                        "line_start": self._find_line_number(log_content, match.start()),
                    }]

                    failure = {
                        "stage": pattern["stage"],
                        "category": pattern["category"],
                        "reason_code": pattern["reason_code"],
                        "severity": "medium",
                        "classifier": "rule",
                        "retryable": pattern["retryable"],
                        "next_action": pattern["next_action"],
                        "summary": f"Matched error pattern: {pattern['pattern_id']}",
                        "signals": signals,
                        "location": location,
                        "related_inputs": {
                            "build_log": build_log_path,
                        },
                        "classified_at": datetime.utcnow().isoformat(),
                    }

                    # Save failure.json
                    cve_dir = os.path.join(self.workdir, self.cve_id)
                    failure_path = os.path.join(cve_dir, "failure.json")
                    with open(failure_path, "w") as f:
                        json.dump(failure, f, indent=2, ensure_ascii=False)

                    return failure

        # No pattern matched
        failure = {
            "stage": "unknown",
            "category": "unknown",
            "reason_code": "unrecognized",
            "severity": "high",
            "classifier": "rule",
            "retryable": False,
            "next_action": "manual_required",
            "summary": "Build failure not recognized by any rule pattern",
            "signals": [{
                "pattern": "unrecognized",
                "source": build_log_path,
            }],
            "location": {},
            "related_inputs": {
                "build_log": build_log_path,
            },
            "classified_at": datetime.utcnow().isoformat(),
        }

        # Save even unrecognized failures
        cve_dir = os.path.join(self.workdir, self.cve_id)
        with open(os.path.join(cve_dir, "failure.json"), "w") as f:
            json.dump(failure, f, indent=2)

        return failure

    def _extract_location(self, log: str, match: re.Match) -> Dict:
        """Extract file and function location from log context."""
        location = {}
        # Try to find file path near the error
        line_start = max(0, match.start() - 500)
        context = log[line_start:match.end() + 200]

        # Look for file paths
        file_match = re.search(r'(?:In file included from|/.*?\.c:\d+)', context)
        if file_match:
            location["file"] = file_match.group(0)

        # Look for function names
        func_match = re.search(r'function\s+`?(\w+)', context)
        if func_match:
            location["function"] = func_match.group(1)

        return location

    @staticmethod
    def _find_line_number(content: str, pos: int) -> int:
        """Find line number for a character position."""
        return content[:pos].count("\n") + 1

    def classify_verify_log(self, verify_log_path: str, dmesg_path: Optional[str] = None) -> Dict:
        """Classify VM verification failure."""
        failure = {
            "stage": "verify",
            "category": "verify",
            "reason_code": "verify_failed",
            "retryable": False,
            "next_action": "manual_required",
            "classified_at": datetime.utcnow().isoformat(),
        }

        if os.path.exists(verify_log_path):
            with open(verify_log_path) as f:
                log = f.read()
            if "ERROR" in log or "failed" in log.lower():
                failure["reason_code"] = "load_failed"
                failure["summary"] = "Module load failed in VM"

        if dmesg_path and os.path.exists(dmesg_path):
            with open(dmesg_path) as f:
                dmesg = f.read()
            failure["dmesg_summary"] = dmesg[-500:] if len(dmesg) > 500 else dmesg

        return failure
```

- [ ] **Step 3: Test imports**

Run: `python3 -c "from agent.tools.kpatch_builder import KpatchBuilder; from agent.tools.failure_classifier import FailureClassifier; print('OK')"`

---

### Task 5: Rewrite Advisor & Reporter

**Files:**
- Create: `agent/tools/rewrite_advisor.py` - Rule-based + LLM-assisted patch rewriting
- Create: `agent/tools/reporter.py` - Generate report.json and summary.json

- [ ] **Step 1: Write agent/tools/rewrite_advisor.py**

```python
"""Rewrite Advisor - rule-based and LLM-assisted patch adaptation."""
import json
import os
import re
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any


class RewriteAdvisor:
    """Advise and generate patch rewrites for target kernel adaptation."""

    REWRITE_STRATEGIES = {
        "context_drift": {
            "description": "Context lines changed, function still exists",
            "auto_allowed": True,
            "semantic_guard": ["security_check_must_keep", "error_return_must_keep"],
        },
        "api_mismatch": {
            "description": "Function signature differs (parameter count/type)",
            "auto_allowed": True,
            "semantic_guard": ["security_check_must_keep", "error_return_must_keep"],
        },
        "missing_include": {
            "description": "Missing header or macro definition",
            "auto_allowed": True,
            "semantic_guard": ["must_not_change_fix_logic"],
        },
        "no_fentry": {
            "description": "Function not traceable, need caller hook",
            "auto_allowed": False,
            "semantic_guard": ["must_not_broaden_fix_scope"],
        },
        "struct_abi": {
            "description": "Structure layout changes - high risk",
            "auto_allowed": False,
            "semantic_guard": [],
        },
    }

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id

    def create_rewrite_plan(self, failure: Dict, change_units: Dict,
                            attempt: int) -> Dict:
        """Create a rewrite plan based on failure analysis and change units."""
        reason_code = failure.get("reason_code", "unknown")
        category = failure.get("category", "unknown")

        # Determine strategy
        strategy = self._map_strategy(reason_code, category)
        strategy_info = self.REWRITE_STRATEGIES.get(strategy, {})

        # Identify affected change unit
        affected_unit = self._find_affected_unit(failure, change_units)
        rewrite_allowed = self._check_rewrite_allowed(affected_unit, strategy_info)

        plan = {
            "attempt_index": attempt,
            "source": "rule",
            "input_failure": "failure.json",
            "target_change_id": affected_unit.get("change_id", "CU-001") if affected_unit else None,
            "decision": "rewrite" if rewrite_allowed else "manual_required",
            "strategy": strategy,
            "semantic_must_keep": strategy_info.get("semantic_guard", []),
            "planned_edits": self._generate_planned_edits(affected_unit, strategy),
            "validation_required": [
                "git apply --check",
                "kpatch-build",
            ],
            "plan_created_at": datetime.utcnow().isoformat(),
        }

        # Save plan
        cve_dir = os.path.join(self.workdir, self.cve_id)
        plan_path = os.path.join(cve_dir, "rewrite_plan.json")
        with open(plan_path, "w") as f:
            json.dump(plan, f, indent=2, ensure_ascii=False)

        return plan

    def apply_rewrite(self, original_patch_path: str, rewrite_plan: Dict,
                      target_source_dir: str, attempt: int) -> Dict:
        """Apply rewrite plan to generate new patch file."""
        patches_dir = os.path.join(self.workdir, self.cve_id, "patches")
        output_path = os.path.join(patches_dir, f"attempt_{attempt}.patch")

        if rewrite_plan.get("decision") != "rewrite":
            return {
                "success": False,
                "reason": "Rewrite not allowed by plan decision",
                "output_path": None,
            }

        # For now, copy original patch as base (real implementation would modify)
        if os.path.exists(original_patch_path):
            shutil.copy2(original_patch_path, output_path)
            result = {
                "success": True,
                "output_path": output_path,
                "strategy": rewrite_plan.get("strategy"),
                "applied_at": datetime.utcnow().isoformat(),
            }
        else:
            result = {
                "success": False,
                "error": f"Original patch not found: {original_patch_path}",
                "output_path": None,
            }

        # Save attempt record
        attempt_record = {
            "attempt_index": attempt,
            "input_patch": original_patch_path,
            "output_patch": output_path if result["success"] else None,
            "rewrite_plan": rewrite_plan.get("strategy"),
            "decision": rewrite_plan.get("decision"),
            "result": result,
        }
        attempt_path = os.path.join(self.workdir, self.cve_id,
                                    f"attempt_{attempt}.json")
        with open(attempt_path, "w") as f:
            json.dump(attempt_record, f, indent=2)

        return result

    def _map_strategy(self, reason_code: str, category: str) -> str:
        """Map failure reason to rewrite strategy."""
        mapping = {
            "hunk_failed": "context_drift",
            "api_mismatch": "api_mismatch",
            "missing_api_or_include": "missing_include",
            "no_fentry": "no_fentry",
            "struct_or_data_change": "struct_abi",
            "field_mismatch": "struct_abi",
            "undefined_symbol": "missing_include",
        }
        return mapping.get(reason_code, "context_drift")

    def _find_affected_unit(self, failure: Dict,
                            change_units: Dict) -> Optional[Dict]:
        """Find which change unit is affected by the failure."""
        location = failure.get("location", {})
        failed_file = location.get("file", "")
        failed_func = location.get("function", "")

        for unit in change_units.get("units", []):
            if failed_func and failed_func in unit.get("function", ""):
                return unit
            if failed_file and failed_file in unit.get("file", ""):
                return unit

        # Return first unit if no match
        if change_units.get("units"):
            return change_units["units"][0]
        return None

    def _check_rewrite_allowed(self, unit: Optional[Dict],
                               strategy_info: Dict) -> bool:
        """Check if rewrite is allowed for this change unit and strategy."""
        if not unit:
            return False
        if not unit.get("rewrite_allowed", True):
            return False
        if not strategy_info.get("auto_allowed", False):
            return False
        return True

    def _generate_planned_edits(self, unit: Optional[Dict],
                                 strategy: str) -> List[Dict]:
        """Generate planned edit descriptions."""
        if not unit:
            return []

        edit = {
            "file": unit.get("file", "unknown"),
            "function": unit.get("function", "unknown"),
            "description": f"Apply {strategy} rewrite for {unit.get('change_id', 'unknown')}",
        }
        return [edit]
```

- [ ] **Step 2: Write agent/tools/reporter.py**

```python
"""Reporter - generates report.json and summary.json from CVE processing results."""
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any


class Reporter:
    """Generate structured reports from CVE processing artifacts."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.cve_dir = os.path.join(workdir, cve_id)

    def generate_report(self) -> Dict:
        """Generate report.json for a single CVE."""
        state = self._read_json("state.json")
        patch_ir = self._read_json("patch_ir.json", {})
        change_units = self._read_json("change_units.json", {})
        failure = self._read_json("failure.json", {})
        verification = self._read_json("verification.json", {})
        events = self._read_json("events.jsonl", [])

        # Determine final status
        status = state.get("status", "failed")
        if status not in ["success", "failed", "manual_required", "skipped"]:
            status = "failed"

        report = {
            "cve_id": self.cve_id,
            "kernel_version": self._get_kernel_version(),
            "status": status,
            "created_at": state.get("created_at", ""),
            "updated_at": state.get("updated_at", ""),
            "state": state.get("state", ""),
            "attempts": state.get("attempt", 0),
            "sources": {
                "nvd": os.path.join(self.cve_dir, "metadata", "raw_nvd.json")
                if os.path.exists(os.path.join(self.cve_dir, "metadata", "raw_nvd.json"))
                else None,
            },
            "patch_ir": {
                "files": patch_ir.get("files", []),
                "functions": patch_ir.get("functions", []),
                "risk_tags": patch_ir.get("risk_tags", []),
                "semantic_summary": patch_ir.get("semantic_summary", ""),
            },
            "change_units": change_units.get("units", []),
            "failure": {
                "category": failure.get("category"),
                "reason_code": failure.get("reason_code"),
                "summary": failure.get("summary"),
                "next_action": failure.get("next_action"),
            } if failure else None,
            "artifact": {
                "path": os.path.join(self.cve_dir, "artifacts", "livepatch.ko")
                if os.path.exists(os.path.join(self.cve_dir, "artifacts", "livepatch.ko"))
                else None,
                "sha256": self._read_sha256(),
            },
            "verification": verification,
            "events": events[-10:] if events else [],  # Last 10 events
            "reproducibility": {
                "kernel_version": self._get_kernel_version(),
                "workdir": self.workdir,
            },
        }

        # Write report
        report_path = os.path.join(self.cve_dir, "report.json")
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return report

    def generate_summary(self, cve_ids: List[str]) -> Dict:
        """Generate summary.json for the entire batch run."""
        reports = []
        success_count = 0
        failed_count = 0
        manual_count = 0
        skipped_count = 0

        for cve_id in cve_ids:
            report_path = os.path.join(self.workdir, cve_id, "report.json")
            if os.path.exists(report_path):
                with open(report_path) as f:
                    report = json.load(f)
                reports.append(report)
                status = report.get("status", "")
                if status == "success":
                    success_count += 1
                elif status == "failed":
                    failed_count += 1
                elif status == "manual_required":
                    manual_count += 1
                elif status == "skipped":
                    skipped_count += 1

        summary = {
            "generated_at": datetime.utcnow().isoformat(),
            "kernel_version": self._get_kernel_version(),
            "total_cves": len(cve_ids),
            "results": {
                "success": success_count,
                "failed": failed_count,
                "manual_required": manual_count,
                "skipped": skipped_count,
            },
            "success_rate": round(success_count / len(cve_ids) * 100, 1)
            if cve_ids else 0.0,
            "cve_reports": [
                {
                    "cve_id": r.get("cve_id"),
                    "status": r.get("status"),
                    "attempts": r.get("attempts"),
                    "failure_category": r.get("failure", {}).get("category")
                    if r.get("failure") else None,
                }
                for r in reports
            ],
        }

        summary_path = os.path.join(self.workdir, "summary.json")
        with open(summary_path, "w") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        return summary

    def _read_json(self, filename: str, default=None) -> Any:
        path = os.path.join(self.cve_dir, filename)
        if not os.path.exists(path):
            return default if default is not None else {}
        with open(path) as f:
            return json.load(f)

    def _get_kernel_version(self) -> str:
        run_config_path = os.path.join(self.workdir, "run_config.json")
        if os.path.exists(run_config_path):
            with open(run_config_path) as f:
                config = json.load(f)
                return config.get("kernel_version", "6.6.102-5.2.an23.x86_64")
        return "6.6.102-5.2.an23.x86_64"

    def _read_sha256(self) -> Optional[str]:
        sha_path = os.path.join(self.cve_dir, "artifacts", "livepatch.ko.sha256")
        if os.path.exists(sha_path):
            with open(sha_path) as f:
                return f.read().strip().split()[0]
        return None
```

- [ ] **Step 3: Test imports**

Run: `python3 -c "from agent.tools.rewrite_advisor import RewriteAdvisor; from agent.tools.reporter import Reporter; print('OK')"`

---

### Task 6: Verifier & MCP/HTTP Service

**Files:**
- Create: `agent/tools/verifier.py` - VM-based livepatch verification

- [ ] **Step 1: Write agent/tools/verifier.py**

```python
"""Verifier - validates livepatch .ko in target VM environment."""
import json
import os
import subprocess
import hashlib
from datetime import datetime
from typing import Dict, Optional, List


class Verifier:
    """Verify livepatch module in Anolis OS VM."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.logs_dir = os.path.join(workdir, cve_id, "logs")
        self.artifacts_dir = os.path.join(workdir, cve_id, "artifacts")
        os.makedirs(self.logs_dir, exist_ok=True)

    def verify(self, ko_path: str, vm_host: Optional[str] = None,
               attempt: int = 1) -> Dict:
        """Run verification suite on the .ko module."""
        verify_log = os.path.join(self.logs_dir, f"verify_{attempt}.log")
        dmesg_log = os.path.join(self.logs_dir, f"dmesg_{attempt}.log")

        result = {
            "artifact": {
                "path": ko_path,
                "sha256": self._hash_file(ko_path) if ko_path and os.path.exists(ko_path) else None,
            },
            "target_kernel": self._get_target_kernel(),
            "load": None,
            "runtime_check": None,
            "unload": None,
            "dmesg": dmesg_log,
            "result": "not_tested",
        }

        if not ko_path or not os.path.exists(ko_path):
            result["result"] = "not_tested"
            result["error"] = f"Artifact not found: {ko_path}"
            self._save_verification(result)
            return result

        if vm_host:
            # Remote verification via SSH
            result = self._verify_remote(ko_path, vm_host, verify_log, dmesg_log)
        else:
            # Local verification (modinfo check only, no actual load)
            result = self._verify_local(ko_path, verify_log)

        self._save_verification(result)
        return result

    def _verify_local(self, ko_path: str, verify_log: str) -> Dict:
        """Local modinfo-based verification (no kernel load)."""
        result = {
            "artifact": {
                "path": ko_path,
                "sha256": self._hash_file(ko_path),
            },
            "target_kernel": self._get_target_kernel(),
            "load": None,
            "runtime_check": None,
            "unload": None,
            "dmesg": None,
            "result": "verification_local_only",
        }

        # Check modinfo
        try:
            with open(verify_log, "w") as log:
                proc = subprocess.run(
                    ["modinfo", ko_path],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    timeout=30,
                )
            result["modinfo_return_code"] = proc.returncode
            result["modinfo_valid"] = proc.returncode == 0
        except FileNotFoundError:
            result["modinfo_error"] = "modinfo not available"

        return result

    def _verify_remote(self, ko_path: str, vm_host: str,
                       verify_log: str, dmesg_log: str) -> Dict:
        """Remote verification via SSH to target VM."""
        result = {
            "artifact": {
                "path": ko_path,
                "sha256": self._hash_file(ko_path),
            },
            "target_kernel": self._get_target_kernel(),
            "load": None,
            "runtime_check": None,
            "unload": None,
            "dmesg": dmesg_log,
        }

        with open(verify_log, "w") as log:
            # Transfer file
            try:
                subprocess.run(
                    ["scp", ko_path, f"{vm_host}:/tmp/livepatch.ko"],
                    stdout=log, stderr=subprocess.STDOUT, timeout=60,
                )
            except Exception as e:
                log.write(f"SCP failed: {e}\n")

            # Check uname
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "uname -r"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30,
                )
                uname = proc.stdout.decode().strip()
                log.write(f"Target uname -r: {uname}\n")
                result["target_kernel"] = uname
            except Exception as e:
                log.write(f"SSH uname failed: {e}\n")

            # Load module
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "kpatch load /tmp/livepatch.ko; echo 'RC:' $?"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30,
                )
                load_output = proc.stdout.decode()
                log.write(f"Load output: {load_output}\n")
                load_rc = 0 if "RC:0" in load_output else 1
                result["load"] = {"return_code": load_rc}
            except Exception as e:
                log.write(f"Load failed: {e}\n")
                result["load"] = {"return_code": -1, "error": str(e)}

            # Check kpatch list
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "kpatch list"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30,
                )
                result["runtime_check"] = {
                    "result": "check_performed",
                    "kpatch_list": proc.stdout.decode(),
                }
            except Exception as e:
                log.write(f"kpatch list failed: {e}\n")

            # Unload
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "kpatch unload livepatch; echo 'RC:' $?"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30,
                )
                unload_output = proc.stdout.decode()
                log.write(f"Unload output: {unload_output}\n")
                unload_rc = 0 if "RC:0" in unload_output else 1
                result["unload"] = {"return_code": unload_rc}
            except Exception as e:
                log.write(f"Unload failed: {e}\n")
                result["unload"] = {"return_code": -1, "error": str(e)}

            # Collect dmesg
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "dmesg | tail -200"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=30,
                )
                with open(dmesg_log, "w") as dm:
                    dm.write(proc.stdout.decode())
                result["dmesg"] = dmesg_log
            except Exception as e:
                log.write(f"dmesg failed: {e}\n")

        # Determine overall result
        load_ok = result.get("load", {}).get("return_code") == 0
        unload_ok = result.get("unload", {}).get("return_code") == 0
        result["result"] = "passed" if (load_ok and unload_ok) else "failed"

        return result

    def _save_verification(self, result: Dict):
        cve_dir = os.path.join(self.workdir, self.cve_id)
        path = os.path.join(cve_dir, "verification.json")
        with open(path, "w") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _hash_file(path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def _get_target_kernel(self) -> str:
        run_config = os.path.join(self.workdir, "run_config.json")
        if os.path.exists(run_config):
            with open(run_config) as f:
                return json.load(f).get("kernel_version", "6.6.102-5.2.an23.x86_64")
        return "6.6.102-5.2.an23.x86_64"
```

- [ ] **Step 2: Test imports**

Run: `python3 -c "from agent.tools.verifier import Verifier; print('OK')"`

---

### Task 7: Integration - Agent Orchestrator

**Files:**
- Modify: `agent/__main__.py` - Add full orchestration loop
- Modify: `agent/planner.py` - Wire up all tools

- [ ] **Step 1: Update agent/__main__.py with full orchestration**

Integrate all tools into the CLI workflow. The orchestrator reads CVE list, initializes state, and runs the processing loop for each CVE.

- [ ] **Step 2: Run end-to-end test**

Run with sample CVE list, verify report.json and summary.json are generated.

---

### Task 8: Failure Pattern Rules & Knowledge Base

**Files:**
- Create: `agent/knowledge/rules/failure_patterns.yaml` - YAML rule definitions
- Create: `agent/knowledge/rules/rewrite_strategies.yaml` - Strategy definitions

- [ ] **Step 1: Write failure_patterns.yaml**

```yaml
# Failure pattern rules for kpatch-build log classification
# Format from v1.md section 4.8.1

- pattern_id: apply.hunk_failed
  category: patch_apply
  reason_code: hunk_failed
  matchers:
    - "hunk FAILED"
    - "patch does not apply"
    - "fuzz"
  action: rewrite
  auto_retry_allowed: true
  requires_human_review: false

- pattern_id: compile.api_args
  category: compile
  reason_code: api_mismatch
  matchers:
    - "too many arguments to function"
    - "too few arguments to function"
  action: rewrite
  auto_retry_allowed: true
  requires_human_review: false

- pattern_id: kpatch.no_fentry
  category: kpatch_limit
  reason_code: no_fentry
  matchers:
    - "no fentry call"
    - "function is not traceable"
  action: manual_required
  auto_retry_allowed: false
  requires_human_review: true

- pattern_id: kpatch.data_change
  category: kpatch_limit
  reason_code: struct_or_data_change
  matchers:
    - "data structure layout change"
    - "static variable changed"
    - "unreconcilable difference"
  action: manual_required
  auto_retry_allowed: false
  requires_human_review: true

- pattern_id: env.no_vmlinux
  category: env_missing
  reason_code: missing_vmlinux
  matchers:
    - "vmlinux not found"
    - "cannot find vmlinux"
  action: fix_environment
  auto_retry_allowed: false
  requires_human_review: false
```

- [ ] **Step 2: Write rewrite_strategies.yaml**

```yaml
# Rewrite strategies for patch adaptation
# From v1.md section 4.9

- strategy_id: context_drift
  description: "Re-contextualize hunk to match target source tree"
  allowed: true
  semantic_guards:
    - "must_preserve_all_added_checks"
    - "must_preserve_error_return_paths"
  validation:
    - "git apply --check"

- strategy_id: api_mismatch
  description: "Adapt function call to match target kernel API"
  allowed: true
  semantic_guards:
    - "must_preserve_security_boundary_checks"
    - "must_preserve_error_return_paths"
  validation:
    - "git apply --check"
    - "kpatch-build"

- strategy_id: no_fentry_hoist
  description: "Move fix to a hookable caller function"
  allowed: false
  requires_human_review: true
  semantic_guards:
    - "must_not_broaden_fix_scope"
    - "must_cover_all_vulnerability_paths"
  validation:
    - "manual_semantic_review"

- strategy_id: struct_abi
  description: "Structure ABI change - not auto-rewritable"
  allowed: false
  requires_human_review: true
  semantic_guards:
    - "do_not_auto_rewrite_abi_changes"
  validation: []
```

---

### Task 9: Tests

**Files:**
- Create: `tests/test_state.py` - StateManager tests
- Create: `tests/test_patch_parser.py` - PatchParser tests
- Create: `tests/test_failure_classifier.py` - FailureClassifier tests
- Create: `tests/test_rewrite_advisor.py` - RewriteAdvisor tests
- Create: `tests/test_data/` - Test fixtures
  - Create: `sample.patch`
  - Create: `sample_build.log`

- [ ] **Step 1: Write tests/test_state.py**

```python
"""Tests for StateManager."""
import os
import json
import tempfile
import pytest
from agent.state import StateManager, VALID_STATES, VALID_FINAL_STATUSES


class TestStateManager:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.sm = StateManager(self.tmpdir)
        self.sm.init_run_config(["CVE-2026-0001"], "6.6.102-5.2.an23.x86_64")

    def test_init_run_config(self):
        config = self.sm.get_run_config()
        assert config["kernel_version"] == "6.6.102-5.2.an23.x86_64"
        assert config["cve_ids"] == ["CVE-2026-0001"]
        assert config["max_attempts"] == 5

    def test_init_cve_state(self):
        state = self.sm.init_cve_state("CVE-2026-0001")
        assert state["cve_id"] == "CVE-2026-0001"
        assert state["state"] == "TaskCreated"
        assert state["attempt"] == 0
        assert state["status"] is None

    def test_transition_to(self):
        self.sm.init_cve_state("CVE-2026-0001")
        state = self.sm.transition_to(
            "CVE-2026-0001", "CveResolved",
            reason="NVD query completed")
        assert state["state"] == "CveResolved"

    def test_increment_attempt(self):
        self.sm.init_cve_state("CVE-2026-0001")
        attempt = self.sm.increment_attempt("CVE-2026-0001")
        assert attempt == 1
        attempt = self.sm.increment_attempt("CVE-2026-0001")
        assert attempt == 2

    def test_set_final_status(self):
        self.sm.init_cve_state("CVE-2026-0001")
        self.sm.set_final_status("CVE-2026-0001", "success")
        state = self.sm.get_state("CVE-2026-0001")
        assert state["status"] == "success"

    def test_valid_states(self):
        assert "TaskCreated" in VALID_STATES
        assert "ReportWritten" in VALID_STATES
        assert len(VALID_STATES) == 16

    def test_valid_final_statuses(self):
        assert "success" in VALID_FINAL_STATUSES
        assert "failed" in VALID_FINAL_STATUSES
        assert "manual_required" in VALID_FINAL_STATUSES
```

- [ ] **Step 2: Write test data files**

Create a sample patch and build log for testing.

- [ ] **Step 3: Write tests/test_patch_parser.py**

```python
"""Tests for PatchParser."""
import os
import tempfile
import pytest
from agent.tools.patch_parser import PatchParser


SAMPLE_PATCH = """From: Test Author <test@kernel.org>
Subject: [PATCH] Fix boundary check in example function

diff --git a/net/example.c b/net/example.c
index abc..def 100644
--- a/net/example.c
+++ b/net/example.c
@@ -100,6 +100,10 @@ int example_check(struct sk_buff *skb, unsigned int len)
 {
 	int ret = 0;
 
+	if (len > MAX_LEN) {
+		return -EINVAL;
+	}
+
 	ret = do_something(skb, len);
 	return ret;
 }
"""

BUILD_FAILURE_LOG = """
In file included from net/example.c:10:
net/example.c: In function 'example_check':
net/example.c:105:13: error: too many arguments to function 'do_something'
  105 |         ret = do_something(skb, len, flag);
      |               ^~~~~~~~~~~
"""


class TestPatchParser:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.patch_path = os.path.join(self.tmpdir, "test.patch")
        with open(self.patch_path, "w") as f:
            f.write(SAMPLE_PATCH)

    def test_parse_patch_basic(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        assert len(patch_ir["files"]) >= 1
        assert any("example" in f["path"] for f in patch_ir["files"])

    def test_change_units_generated(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        # change_units.json should exist
        change_path = os.path.join(self.tmpdir, "CVE-2026-0001", "change_units.json")
        assert os.path.exists(change_path)

    def test_semantic_role_detected(self):
        parser = PatchParser(self.tmpdir, "CVE-2026-0001")
        patch_ir = parser.parse_patch(self.patch_path)
        summary = patch_ir.get("semantic_summary", "")
        assert "boundary" in summary or "security" in summary
```

- [ ] **Step 4: Write tests/test_failure_classifier.py**

```python
"""Tests for FailureClassifier."""
import os
import tempfile
import pytest
from agent.tools.failure_classifier import FailureClassifier


class TestFailureClassifier:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmpdir, "CVE-2026-0001"))

    def test_classify_api_mismatch(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("""
In file included from net/example.c:10:
net/example.c:105:13: error: too many arguments to function 'do_something'
  105 |         ret = do_something(skb, len, flag);
""")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "compile"
        assert failure["reason_code"] == "api_mismatch"
        assert failure["retryable"] is True

    def test_classify_no_fentry(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("no fentry call found for function example_check\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "kpatch_limit"
        assert failure["reason_code"] == "no_fentry"

    def test_classify_hunk_failed(self):
        log_path = os.path.join(self.tmpdir, "build.log")
        with open(log_path, "w") as f:
            f.write("error: patch failed: net/example.c:100\nhunk FAILED\n")
        classifier = FailureClassifier(self.tmpdir, "CVE-2026-0001")
        failure = classifier.classify(log_path)
        assert failure["category"] == "patch_apply"
        assert failure["reason_code"] == "hunk_failed"
```

- [ ] **Step 5: Write tests/test_rewrite_advisor.py**

```python
"""Tests for RewriteAdvisor."""
import os
import json
import tempfile
import pytest
from agent.tools.rewrite_advisor import RewriteAdvisor


class TestRewriteAdvisor:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.tmpdir, "CVE-2026-0001", "patches"))
        self.cve_dir = os.path.join(self.tmpdir, "CVE-2026-0001")
        self.advisor = RewriteAdvisor(self.tmpdir, "CVE-2026-0001")

    def test_rewrite_plan_api_mismatch(self):
        failure = {
            "category": "compile",
            "reason_code": "api_mismatch",
            "location": {"file": "net/example.c", "function": "example_check"},
            "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001",
                "file": "net/example.c",
                "function": "example_check",
                "rewrite_allowed": True,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "rewrite"
        assert plan["strategy"] == "api_mismatch"

    def test_rewrite_plan_struct_abi(self):
        failure = {
            "category": "kpatch_limit",
            "reason_code": "struct_or_data_change",
            "retryable": False,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001",
                "file": "net/example.c",
                "function": "example_check",
                "rewrite_allowed": False,
            }]
        }
        plan = self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        assert plan["decision"] == "manual_required"

    def test_rewrite_plan_file_saved(self):
        failure = {
            "category": "compile",
            "reason_code": "api_mismatch",
            "location": {"file": "net/example.c"},
            "retryable": True,
        }
        change_units = {
            "units": [{
                "change_id": "CU-001",
                "file": "net/example.c",
                "function": "example_check",
                "rewrite_allowed": True,
            }]
        }
        self.advisor.create_rewrite_plan(failure, change_units, attempt=1)
        plan_path = os.path.join(self.cve_dir, "rewrite_plan.json")
        assert os.path.exists(plan_path)
```

- [ ] **Step 6: Run all tests**

Run: `cd /tmp/opencode/kernel-livepatch-agent && python3 -m pytest tests/ -v`
