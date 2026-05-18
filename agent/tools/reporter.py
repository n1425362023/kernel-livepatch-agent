"""Reporter - generates report.json and summary.json from CVE processing results."""
import json
import os
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any


class Reporter:
    """Generate structured reports from CVE processing artifacts."""

    def __init__(self, workdir: str, cve_id: str = ""):
        self.workdir = workdir
        self.cve_id = cve_id
        self.cve_dir = os.path.join(workdir, cve_id) if cve_id else workdir

    def generate_report(self) -> Dict:
        state = self._read_json("state.json")
        patch_ir = self._read_json("patch_ir.json", {})
        change_units = self._read_json("change_units.json", {})
        failure = self._read_json("failure.json", {})
        verification = self._read_json("verification.json", {})
        events = self._read_json("events.jsonl", [])
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
                if os.path.exists(os.path.join(self.cve_dir, "metadata", "raw_nvd.json")) else None,
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
                if os.path.exists(os.path.join(self.cve_dir, "artifacts", "livepatch.ko")) else None,
                "sha256": self._read_sha256(),
            },
            "verification": verification,
            "events": events[-10:] if events else [],
            "reproducibility": {
                "kernel_version": self._get_kernel_version(),
                "workdir": self.workdir,
            },
        }
        with open(os.path.join(self.cve_dir, "report.json"), "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        return report

    def generate_summary(self, cve_ids: List[str]) -> Dict:
        reports = []
        success_count = failed_count = manual_count = skipped_count = 0
        for cve_id in cve_ids:
            report_path = os.path.join(self.workdir, cve_id, "report.json")
            if os.path.exists(report_path):
                with open(report_path) as f:
                    report = json.load(f)
                reports.append(report)
                status = report.get("status", "")
                if status == "success": success_count += 1
                elif status == "failed": failed_count += 1
                elif status == "manual_required": manual_count += 1
                elif status == "skipped": skipped_count += 1
        summary = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "kernel_version": self._get_kernel_version(),
            "total_cves": len(cve_ids),
            "results": {"success": success_count, "failed": failed_count,
                        "manual_required": manual_count, "skipped": skipped_count},
            "success_rate": round(success_count / len(cve_ids) * 100, 1) if cve_ids else 0.0,
            "cve_reports": [{"cve_id": r.get("cve_id"), "status": r.get("status"),
                             "attempts": r.get("attempts"),
                             "failure_category": r.get("failure", {}).get("category") if r.get("failure") else None}
                            for r in reports],
        }
        with open(os.path.join(self.workdir, "summary.json"), "w") as f:
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
                return json.load(f).get("kernel_version", "6.6.102-5.2.an23.x86_64")
        return "6.6.102-5.2.an23.x86_64"

    def _read_sha256(self) -> Optional[str]:
        sha_path = os.path.join(self.cve_dir, "artifacts", "livepatch.ko.sha256")
        if os.path.exists(sha_path):
            with open(sha_path) as f:
                return f.read().strip().split()[0]
        return None
