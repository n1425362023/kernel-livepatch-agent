"""Verifier - validates livepatch .ko in target VM environment."""
import json
import os
import re
import subprocess
import hashlib
from datetime import datetime, timezone
from typing import Dict, Optional


class Verifier:
    """Verify livepatch module in Anolis OS VM."""

    def __init__(self, workdir: str, cve_id: str):
        self.workdir = workdir
        self.cve_id = cve_id
        self.logs_dir = os.path.join(workdir, cve_id, "logs")
        self.artifacts_dir = os.path.join(workdir, cve_id, "artifacts")
        os.makedirs(self.logs_dir, exist_ok=True)

    @staticmethod
    def _validate_vm_host(vm_host: str) -> bool:
        """Validate vm_host format: user@hostname or hostname only. Prevents shell injection."""
        return bool(re.match(r'^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$', vm_host))

    def verify(self, ko_path: str, vm_host: Optional[str] = None, attempt: int = 1) -> Dict:
        verify_log = os.path.join(self.logs_dir, f"verify_{attempt}.log")
        dmesg_log = os.path.join(self.logs_dir, f"dmesg_{attempt}.log")
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path) if ko_path and os.path.exists(ko_path) else None},
            "target_kernel": self._get_target_kernel(),
            "load": None, "runtime_check": None, "unload": None,
            "dmesg": dmesg_log, "result": "not_tested",
        }
        if not ko_path or not os.path.exists(ko_path):
            result["result"] = "not_tested"
            result["error"] = f"Artifact not found: {ko_path}"
            self._save_verification(result)
            return result
        if vm_host:
            result = self._verify_remote(ko_path, vm_host, verify_log, dmesg_log)
        else:
            result = self._verify_local(ko_path, verify_log)
        self._save_verification(result)
        return result

    def _verify_local(self, ko_path: str, verify_log: str) -> Dict:
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
            "target_kernel": self._get_target_kernel(),
            "load": None, "runtime_check": None, "unload": None, "dmesg": None,
            "result": "verification_local_only",
        }
        try:
            with open(verify_log, "w") as log:
                proc = subprocess.run(["modinfo", ko_path], stdout=log, stderr=subprocess.STDOUT, timeout=30)
            result["modinfo_return_code"] = proc.returncode
            result["modinfo_valid"] = proc.returncode == 0
        except FileNotFoundError:
            result["modinfo_error"] = "modinfo not available"
        return result

    def _verify_remote(self, ko_path: str, vm_host: str, verify_log: str, dmesg_log: str) -> Dict:
        if not self._validate_vm_host(vm_host):
            return {
                "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
                "target_kernel": self._get_target_kernel(),
                "load": None, "runtime_check": None, "unload": None, "dmesg": dmesg_log,
                "result": "failed",
                "error": f"Invalid vm_host format: {vm_host}",
            }
        result = {
            "artifact": {"path": ko_path, "sha256": self._hash_file(ko_path)},
            "target_kernel": self._get_target_kernel(),
            "load": None, "runtime_check": None, "unload": None, "dmesg": dmesg_log,
        }
        with open(verify_log, "w") as log:
            try:
                subprocess.run(["scp", ko_path, f"{vm_host}:/tmp/livepatch.ko"], stdout=log, stderr=subprocess.STDOUT, timeout=60)
            except Exception as e:
                log.write(f"SCP failed: {e}\n")
            try:
                proc = subprocess.run(["ssh", vm_host, "uname", "-r"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                uname = proc.stdout.decode().strip()
                log.write(f"Target uname -r: {uname}\n")
                result["target_kernel"] = uname
            except Exception as e:
                log.write(f"SSH uname failed: {e}\n")
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "kpatch", "load", "/tmp/livepatch.ko"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                log.write(f"Load output: {proc.stdout.decode()}\n")
                result["load"] = {"return_code": proc.returncode}
            except Exception as e:
                log.write(f"Load failed: {e}\n")
                result["load"] = {"return_code": -1, "error": str(e)}
            try:
                proc = subprocess.run(["ssh", vm_host, "kpatch", "list"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
                result["runtime_check"] = {"result": "check_performed", "kpatch_list": proc.stdout.decode()}
            except Exception as e:
                log.write(f"kpatch list failed: {e}\n")
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "kpatch", "unload", "livepatch"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                log.write(f"Unload output: {proc.stdout.decode()}\n")
                result["unload"] = {"return_code": proc.returncode}
            except Exception as e:
                log.write(f"Unload failed: {e}\n")
                result["unload"] = {"return_code": -1, "error": str(e)}
            try:
                proc = subprocess.run(
                    ["ssh", vm_host, "dmesg"],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30,
                )
                dmesg_output = proc.stdout.decode()
                with open(dmesg_log, "w") as dm:
                    dm.write(dmesg_output[-10000:] if len(dmesg_output) > 10000 else dmesg_output)
                result["dmesg"] = dmesg_log
            except Exception as e:
                log.write(f"dmesg failed: {e}\n")
        load_ok = result.get("load", {}).get("return_code") == 0
        unload_ok = result.get("unload", {}).get("return_code") == 0
        result["result"] = "passed" if (load_ok and unload_ok) else "failed"
        return result

    def _save_verification(self, result: Dict):
        with open(os.path.join(self.workdir, self.cve_id, "verification.json"), "w") as f:
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
