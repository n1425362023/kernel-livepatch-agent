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

    def cve_dir(self, cve_id: str) -> str:
        return os.path.join(self.workdir, cve_id)

    def ensure_subdir(self, cve_id: str, subdir: str) -> str:
        path = os.path.join(self.workdir, cve_id, subdir)
        os.makedirs(path, exist_ok=True)
        return path

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
