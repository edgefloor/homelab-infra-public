#!/usr/bin/env python3
"""Prove recovery from retained n8n state without touching production state.

Run as root on the n8n host. Uses the installed immutable release, a new UID,
and loopback-only namespaces. No workflow or external request is executed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

import rehearse_n8n_restore as rehearsal


def fingerprint(paths):
    return {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError("run as root on the n8n host")
    os.umask(0o077)
    source = args.state.resolve(strict=True)
    if not source.is_relative_to("/var/backups/n8n") or source == rehearsal.SOURCE:
        raise ValueError("source must be retained state under /var/backups/n8n")
    files = [
        source / name
        for name in (
            "config",
            "database.sqlite",
            "database.sqlite-wal",
            "database.sqlite-shm",
        )
        if (source / name).exists()
    ]
    if not {"config", "database.sqlite"} <= {p.name for p in files}:
        raise ValueError("the retained database and matching config are both required")
    if any(p.is_symlink() or not p.is_file() for p in files):
        raise ValueError("backup inputs must be regular files")
    original = rehearsal.service_identity()
    release = Path(original["release"])
    if not release.is_relative_to("/opt/n8n/releases"):
        raise ValueError("production must use an immutable installed release")
    version = json.loads((release / "node_modules/n8n/package.json").read_text())[
        "version"
    ]
    if version != "2.43.8":
        raise ValueError("review this verifier before using another n8n version")
    original_database = rehearsal.inspect_database(rehearsal.SOURCE / "database.sqlite")
    before = fingerprint(files)
    directory = Path(tempfile.mkdtemp(prefix="homelab-retained-restore-"))
    receipt = {
        "schema": 1,
        "status": "failed",
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source": str(source),
        "source_sha256": before,
        "release": str(release),
        "version": version,
    }
    account = process = log_stream = None
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    logs = Path(tempfile.mkdtemp(prefix="homelab-retained-logs-"))
    try:
        state = directory / ".n8n"
        state.mkdir(mode=0o700)
        for path in files:
            shutil.copy2(path, state / path.name)
        receipt["before"] = rehearsal.inspect_database(state / "database.sqlite")
        account = rehearsal.create_rehearsal_account()
        for path in [directory, state, *state.iterdir()]:
            os.chown(path, account.pw_uid, account.pw_gid)
        receipt["isolation"] = rehearsal.verify_isolation(
            directory, account, original["MainPID"], source
        )
        rehearsal.bounded_candidate(
            release,
            directory,
            ["unpublish:workflow", "--all"],
            logs / "unpublish.log",
            account,
        )
        if rehearsal.inspect_database(state / "database.sqlite")["counts"][
            "active_workflows"
        ]:
            raise RuntimeError("disposable workflows remain active")
        export = directory / "credentials.json"
        arguments = [
            "export:credentials",
            "--all",
            "--decrypted",
            "--output=" + str(export),
        ]
        rehearsal.bounded_candidate(
            release, directory, arguments, logs / "correct-key.log", account
        )
        credentials = json.loads(export.read_text())
        if (
            len(credentials) != receipt["before"]["counts"]["credentials"]
            or not credentials
            or any(not isinstance(item.get("data"), dict) for item in credentials)
        ):
            raise RuntimeError("retained credentials were not recovered")
        receipt["decrypted_credentials"] = len(credentials)
        del credentials
        export.unlink()
        correct_config = (state / "config").read_bytes()
        (state / "config").write_text(
            json.dumps({"encryptionKey": "deliberately-wrong-recovery-key"})
        )
        try:
            rehearsal.bounded_candidate(
                release, directory, arguments, logs / "wrong-key.log", account
            )
        except RuntimeError:
            failure = (logs / "wrong-key.log").read_text()
            if "could not be decrypted" not in failure.lower():
                raise RuntimeError(
                    "wrong-key failure was not the expected native decryption error"
                )
            receipt["wrong_key_rejected_by_native_decryption"] = True
        else:
            raise RuntimeError("credentials unexpectedly decrypted with the wrong key")
        finally:
            export.unlink(missing_ok=True)
            (state / "config").write_bytes(correct_config)
            del correct_config
        # Prove recovery after the bad-key attempt, not just detection of failure.
        rehearsal.bounded_candidate(
            release, directory, arguments, logs / "recovered-key.log", account
        )
        if len(json.loads(export.read_text())) != receipt["decrypted_credentials"]:
            raise RuntimeError(
                "correct key did not recover the credentials after failure"
            )
        export.unlink()
        log_stream = (logs / "startup.log").open("wb")
        process = subprocess.Popen(
            rehearsal.candidate_command(release, directory, ["start"], account),
            stdout=log_stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            cwd=directory,
        )
        for _ in range(45):
            if process.poll() is not None:
                raise RuntimeError("restored service exited before readiness")
            if os.readlink(f"/proc/{process.pid}/ns/net") == os.readlink(
                "/proc/self/ns/net"
            ):
                time.sleep(0.2)
                continue
            try:
                prefix = ["nsenter", "-t", str(process.pid), "-n", "--"]
                code = rehearsal.command(
                    prefix
                    + [
                        "curl",
                        "-s",
                        "--max-time",
                        "2",
                        "-o",
                        "/dev/null",
                        "-w",
                        "%{http_code}",
                        "http://127.0.0.1:15678/healthz/readiness",
                    ]
                )
                if code == "200":
                    receipt["readiness_http"] = 200
                    receipt["unauthenticated_workflows_http"] = int(
                        rehearsal.command(
                            prefix
                            + [
                                "curl",
                                "-s",
                                "--max-time",
                                "2",
                                "-o",
                                "/dev/null",
                                "-w",
                                "%{http_code}",
                                "http://127.0.0.1:15678/rest/workflows",
                            ]
                        )
                    )
                    if receipt["unauthenticated_workflows_http"] != 401:
                        raise RuntimeError(
                            "restored service did not enforce native authentication"
                        )
                    break
            except RuntimeError:
                pass
            time.sleep(2)
        else:
            raise RuntimeError("restored readiness/authentication checks failed")
        rehearsal.stop(process)
        receipt["after"] = rehearsal.inspect_database(state / "database.sqlite")
        if receipt["after"]["content_sha256"] != receipt["before"]["content_sha256"]:
            raise RuntimeError(
                "restored account, workflow or credential content changed"
            )
        if receipt["after"]["counts"]["active_workflows"]:
            raise RuntimeError("a restored workflow was activated")
        if fingerprint(files) != before:
            raise RuntimeError("retained backup input changed")
        if rehearsal.service_identity() != original:
            raise RuntimeError("production service changed")
        if (
            rehearsal.inspect_database(rehearsal.SOURCE / "database.sqlite")
            != original_database
        ):
            raise RuntimeError("production account/workflow/credential state changed")
        receipt.update(
            status="passed",
            retained_backup_unchanged=True,
            production_unchanged=True,
            workflows_not_executed=True,
        )
    finally:
        try:
            rehearsal.finalize_rehearsal(
                process, log_stream, account, directory, receipt, args.output
            )
        finally:
            shutil.rmtree(logs)
    print(json.dumps(receipt, indent=2))


if __name__ == "__main__":
    main()
