from __future__ import annotations

import importlib.util
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ansible/roles/homelab_agent_service/files/repository_broker.py"


def git(path, *arguments):
    return subprocess.check_output(
        ["git", *arguments], cwd=path, text=True,
        stderr=subprocess.STDOUT).strip()


class RecordingProvider:
    def __init__(self):
        self.calls = []

    def create_pull_request(self, repository, head, base, title, body):
        self.calls.append((repository, head, base, title, body))
        return {"url": "https://provider.invalid/pulls/7", "number": 7}

    def find_pull_request(self, repository, head, base):
        return None


class UncertainProvider(RecordingProvider):
    def __init__(self):
        super().__init__()
        self.created = None
        self.fail_once = True

    def find_pull_request(self, repository, head, base):
        return self.created

    def create_pull_request(self, repository, head, base, title, body):
        self.calls.append((repository, head, base, title, body))
        self.created = {"url": "https://provider.invalid/pulls/8", "number": 8}
        if self.fail_once:
            self.fail_once = False
            raise self.module.RepositoryError("provider_unavailable")
        return self.created


class RepositoryBrokerTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("repository_broker", SOURCE)
        self.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.module)
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.remote = self.base / "remote.git"
        self.workspaces = self.base / "workspaces"
        self.source.mkdir()
        git(self.source, "init", "-b", "main")
        git(self.source, "config", "user.name", "Fixture")
        git(self.source, "config", "user.email", "fixture@example.invalid")
        (self.source / "version.txt").write_text("1\n")
        git(self.source, "add", "version.txt")
        git(self.source, "commit", "-m", "initial")
        subprocess.check_call(["git", "clone", "--bare", str(self.source), str(self.remote)])
        self.provider = RecordingProvider()
        self.broker = self.module.RepositoryBroker({
            "workspace_root": str(self.workspaces),
            "repositories": {
                "homelab": {
                    "clone_url": str(self.remote),
                    "provider_repository": "edgefloor/homelab-infra",
                    "base_branch": "main",
                    "validation": [["python3", "-c",
                                    "import os; assert 'CREDENTIALS_DIRECTORY' not in os.environ; assert open('version.txt').read().strip() == '2'"]],
                }
            },
        }, provider=self.provider)

    def tearDown(self):
        self.temp.cleanup()

    def test_checkout_validation_push_and_pr_creation_use_the_provider_boundary(self):
        checkout = self.broker.checkout("homelab", "fix/cve-2026-7001", "CVE work")
        path = Path(checkout["path"])
        self.assertEqual("main", checkout["base_branch"])
        self.assertEqual("1\n", (path / "version.txt").read_text())
        (path / "version.txt").write_text("2\n")
        (path / ".git").write_text("gitdir: /attacker-controlled\n")

        with mock.patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": "/secret"}):
            proposal = self.broker.propose(
                checkout["workspace"], title="Fix CVE-2026-7001",
                body="Covers work_1 and occurrence_1")

        self.assertEqual("https://provider.invalid/pulls/7", proposal["pr"])
        self.assertEqual("passed", proposal["validation"][0]["status"])
        self.assertEqual("fix/cve-2026-7001", proposal["branch"])
        self.assertEqual("2", git(self.remote, "show", "refs/heads/fix/cve-2026-7001:version.txt"))
        self.assertEqual(1, len(self.provider.calls))
        self.assertEqual(0o2750, self.broker.metadata.stat().st_mode & 0o7777)

    def test_broker_exposes_no_merge_or_deploy_operation(self):
        self.assertFalse(hasattr(self.broker, "merge"))
        self.assertFalse(hasattr(self.broker, "deploy"))

    def test_broker_rejects_metadata_under_group_writable_parent(self):
        unsafe = self.base / "unsafe"
        unsafe.mkdir()
        os.chmod(unsafe, 0o770)
        with self.assertRaisesRegex(self.module.RepositoryError,
                                    "invalid_metadata_ownership"):
            self.module.RepositoryBroker({
                "workspace_root": str(self.workspaces / "another"),
                "metadata_root": str(unsafe / "metadata"),
                "repositories": {},
            }, provider=self.provider)

    def test_checkout_uses_scoped_credential(self):
        self.broker.push_token = "fixture-token"
        with mock.patch.object(self.broker, "_run", wraps=self.broker._run) as commands:
            self.broker.checkout("homelab", "fix/auth", "authenticated clone")
        clone = next(call for call in commands.call_args_list if "clone" in call.args[0])
        self.assertEqual(clone.kwargs["env"], self.broker._push_env(str(self.remote)))

    def test_checkout_preserves_executable_files(self):
        script = self.source / "run.sh"
        script.write_text("#!/bin/sh\nexit 0\n")
        script.chmod(0o755)
        git(self.source, "add", "run.sh")
        git(self.source, "commit", "-m", "add executable")
        git(self.source, "push", str(self.remote), "main")

        checkout = self.broker.checkout("homelab", "fix/mode", "preserve mode")
        path = Path(checkout["path"])
        self.assertTrue((path / "run.sh").stat().st_mode & 0o100)
        self.assertEqual("", git(path, "status", "--porcelain"))

    def test_installed_git_validation_runs_as_the_configured_identity(self):
        account = __import__("pwd").getpwuid(os.getuid()).pw_name
        broker = self.module.RepositoryBroker({
            "workspace_root": str(self.workspaces / "identity"),
            "validation_user": account,
            "repositories": {"homelab": {
                "clone_url": str(self.remote),
                "provider_repository": "edgefloor/homelab-infra",
                "base_branch": "main",
                "validation": [["env", "GIT_TEST_ASSUME_DIFFERENT_OWNER=1",
                                "git", "diff", "--check"]],
            }},
        }, provider=self.provider)
        checkout = broker.checkout("homelab", "fix/identity", "identity")
        (Path(checkout["path"]) / "version.txt").write_text("2\n")
        proposal = broker.propose(
            checkout["workspace"], title="Validate as Zig", body="identity")
        self.assertEqual("passed", proposal["validation"][0]["status"])

    def test_resume_rejects_contents_changed_after_validation(self):
        checkout = self.broker.checkout(
            "homelab", "fix/content-binding", "bind validated contents")
        path = Path(checkout["path"])
        (path / "version.txt").write_text("2\n")
        original_save = self.broker._save_manifest
        interrupted = False

        def stop_after_validation(manifest):
            nonlocal interrupted
            original_save(manifest)
            proposal = manifest.get("proposal", {})
            if proposal.get("state") == "validated" and not interrupted:
                interrupted = True
                raise self.module.RepositoryError("injected_interruption")

        with mock.patch.object(
                self.broker, "_save_manifest", side_effect=stop_after_validation):
            with self.assertRaisesRegex(self.module.RepositoryError,
                                        "injected_interruption"):
                self.broker.propose(
                    checkout["workspace"], title="Bind contents", body="same request")

        (path / "version.txt").write_text("3\n")
        with self.assertRaisesRegex(self.module.RepositoryError,
                                    "workspace_changed_after_validation"):
            self.broker.propose(
                checkout["workspace"], title="Bind contents", body="same request")
        self.assertEqual([], self.provider.calls)

    def test_retry_reconciles_a_pr_created_before_provider_acknowledgement(self):
        provider = UncertainProvider()
        provider.module = self.module
        self.broker.provider = provider
        checkout = self.broker.checkout(
            "homelab", "fix/retry", "retry partial proposal")
        (Path(checkout["path"]) / "version.txt").write_text("2\n")
        with self.assertRaisesRegex(self.module.RepositoryError,
                                    "provider_unavailable"):
            self.broker.propose(
                checkout["workspace"], title="Retry PR", body="same request")

        proposal = self.broker.propose(
            checkout["workspace"], title="Retry PR", body="same request")

        self.assertEqual("https://provider.invalid/pulls/8", proposal["pr"])
        self.assertEqual(1, len(provider.calls))

    def test_retry_resumes_after_push_failure(self):
        checkout = self.broker.checkout(
            "homelab", "fix/push-retry", "retry failed push")
        (Path(checkout["path"]) / "version.txt").write_text("2\n")
        original_run = self.broker._run
        failed = False

        def fail_first_push(arguments, **kwargs):
            nonlocal failed
            if "push" in arguments and not failed:
                failed = True
                raise self.module.RepositoryError("command_failed", "injected push failure")
            return original_run(arguments, **kwargs)

        with mock.patch.object(self.broker, "_run", side_effect=fail_first_push):
            with self.assertRaisesRegex(self.module.RepositoryError,
                                        "command_failed"):
                self.broker.propose(
                    checkout["workspace"], title="Retry push", body="same request")

        proposal = self.broker.propose(
            checkout["workspace"], title="Retry push", body="same request")

        self.assertTrue(failed)
        self.assertEqual("https://provider.invalid/pulls/7", proposal["pr"])
        self.assertEqual(
            "2", git(self.remote,
                     "show", "refs/heads/fix/push-retry:version.txt"))
        self.assertEqual(1, len(self.provider.calls))

    def test_retry_reconciles_commit_written_before_progress_save(self):
        checkout = self.broker.checkout(
            "homelab", "fix/commit-retry", "retry completed commit")
        path = Path(checkout["path"])
        (path / "version.txt").write_text("2\n")
        original_save = self.broker._save_manifest
        interrupted = False

        def stop_before_committed_progress(manifest):
            nonlocal interrupted
            proposal = manifest.get("proposal", {})
            if proposal.get("state") == "committed" and not interrupted:
                interrupted = True
                raise self.module.RepositoryError("injected_interruption")
            original_save(manifest)

        with mock.patch.object(
                self.broker, "_save_manifest",
                side_effect=stop_before_committed_progress):
            with self.assertRaisesRegex(self.module.RepositoryError,
                                        "injected_interruption"):
                self.broker.propose(
                    checkout["workspace"], title="Retry commit",
                    body="same request")

        committed = git(path, "rev-parse", "HEAD")
        proposal = self.broker.propose(
            checkout["workspace"], title="Retry commit", body="same request")

        self.assertTrue(interrupted)
        self.assertEqual(committed, git(path, "rev-parse", "HEAD"))
        self.assertEqual("https://provider.invalid/pulls/7", proposal["pr"])
        self.assertEqual(
            "2", git(self.remote,
                     "show", "refs/heads/fix/commit-retry:version.txt"))
        self.assertEqual(1, len(self.provider.calls))


if __name__ == "__main__":
    unittest.main()
