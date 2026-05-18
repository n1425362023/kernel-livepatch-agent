"""Planner - decides next action based on CVE state machine."""
import json
import os
from typing import List, Optional, Dict, Any
from agent.state import StateManager, VALID_FINAL_STATUSES


class Planner:
    """Determines next action for each CVE based on its current state."""

    def __init__(self, state_mgr: StateManager):
        self.state_mgr = state_mgr

    def decide_next(self, cve_id: str) -> Dict[str, Any]:
        state = self.state_mgr.get_state(cve_id)
        current = state.get("state", "TaskCreated")
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)

        if state.get("status") in VALID_FINAL_STATUSES:
            return {"action": "done", "reason": "Already in final state"}

        transitions: Dict[str, Any] = {
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
        """After failure classification, decide: retry with rewrite or give up."""
        attempt = state.get("attempt", 0)
        max_attempts = state.get("max_attempts", 5)

        # Check if failure is non-retryable (e.g., no_fentry, struct_abi)
        cve_id = state.get("cve_id", "")
        if cve_id:
            failure_path = os.path.join(self.state_mgr.workdir, cve_id, "failure.json")
            if os.path.exists(failure_path):
                with open(failure_path) as f:
                    failure = json.load(f)
                if not failure.get("retryable", True):
                    return {"action": "done", "next_state": "ManualRequired",
                            "reason": f"Non-retryable failure: {failure.get('reason_code', 'unknown')}"}

        if attempt < max_attempts:
            return {"action": "prepare_rewrite", "next_state": "RewritePrepared"}
        else:
            return {"action": "done", "next_state": "Failed",
                    "reason": f"Max attempts ({max_attempts}) reached"}

    def get_all_cve_dirs(self) -> List[str]:
        items = os.listdir(self.state_mgr.workdir)
        return [d for d in items if d.startswith("CVE-")
                and os.path.isdir(os.path.join(self.state_mgr.workdir, d))]

    def get_active_cves(self) -> List[str]:
        active = []
        for cve_id in self.get_all_cve_dirs():
            state = self.state_mgr.get_state(cve_id)
            if state.get("status") not in VALID_FINAL_STATUSES:
                active.append(cve_id)
        return active
