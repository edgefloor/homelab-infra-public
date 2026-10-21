#!/usr/bin/env python3
"""Credential-owning repository checkout, validation, push, and PR broker."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import tempfile
import uuid
from urllib import error, parse, request


BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$")
WORKSPACE = re.compile(r"repo_[0-9a-f]{32}$")


class RepositoryError(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code = code
        self.detail = detail


class GitHubProvider:
    def __init__(self, token, endpoint="https://api.github.com"):
        self.token = token
        self.endpoint = endpoint.rstrip("/")

    def create_pull_request(self, repository, head, base, title, body):
        payload = json.dumps({"head": head, "base": base, "title": title,
                              "body": body}).encode()
        outgoing = request.Request(
            f"{self.endpoint}/repos/{repository}/pulls", data=payload,
            headers={"Accept": "application/vnd.github+json",
                     "Authorization": "Bearer " + self.token,
                     "Content-Type": "application/json",
                     "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with request.urlopen(outgoing, timeout=30) as response:
                result = json.load(response)
        except error.HTTPError as exc:
            exc.close()
            raise RepositoryError("provider_rejected", str(exc.code)) from exc
        except (OSError, error.URLError, TimeoutError) as exc:
            raise RepositoryError("provider_unavailable") from exc
        return {"url": result["html_url"], "number": result["number"]}

    def find_pull_request(self, repository, head, base):
        owner = repository.split("/", 1)[0]
        query = parse.urlencode({"state": "open", "head": owner + ":" + head,
                                 "base": base, "per_page": 10})
        outgoing = request.Request(
            f"{self.endpoint}/repos/{repository}/pulls?{query}",
            headers={"Accept": "application/vnd.github+json",
                     "Authorization": "Bearer " + self.token,
                     "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with request.urlopen(outgoing, timeout=30) as response:
                values = json.load(response)
        except error.HTTPError as exc:
            exc.close()
            raise RepositoryError("provider_rejected", str(exc.code)) from exc
        except (OSError, error.URLError, TimeoutError) as exc:
            raise RepositoryError("provider_unavailable") from exc
        for value in values:
            if (value.get("head", {}).get("ref") == head and
                    value.get("base", {}).get("ref") == base):
                return {"url": value["html_url"], "number": value["number"]}
        return None


class RepositoryBroker:
    """Keep repository credentials and provider details behind two operations."""

    def __init__(self, config, provider, push_token=None):
        self.root = Path(config["workspace_root"]).resolve()
        self.repositories = config["repositories"]
        self.provider = provider
        self.push_token = push_token
        self.validation_user = config.get("validation_user")
        self.root.mkdir(parents=True, mode=0o2770, exist_ok=True)
        self.metadata = Path(config.get(
            "metadata_root", self.root.parent / (self.root.name + ".metadata")
        )).absolute()
        self._verify_metadata_parent()
        self.metadata.mkdir(mode=0o2750, exist_ok=True)
        self._require_owned(self.metadata)
        os.chmod(self.metadata, 0o2750)
        self._verify_metadata()

    @staticmethod
    def _require_owned(path, directory=True):
        info = path.lstat()
        expected = stat.S_ISDIR if directory else stat.S_ISREG
        if not expected(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RepositoryError("invalid_metadata_ownership")

    def _verify_metadata_parent(self):
        self._require_owned(self.metadata.parent)
        if self.metadata.is_relative_to(self.root):
            raise RepositoryError("invalid_metadata_location")

    def _verify_metadata(self):
        self._verify_metadata_parent()
        self._require_owned(self.metadata)

    @staticmethod
    def _run(arguments, cwd=None, env=None, timeout=1200, run_as=None):
        child_env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        if env:
            child_env.update(env)
        drop_privileges = None
        if run_as:
            account = pwd.getpwnam(run_as)
            if os.geteuid() not in {0, account.pw_uid}:
                raise RepositoryError("invalid_configuration",
                                      "validation_user requires a root broker")
            if os.geteuid() == 0 and account.pw_uid != 0:
                def drop_privileges():
                    os.initgroups(account.pw_name, account.pw_gid)
                    os.setgid(account.pw_gid)
                    os.setuid(account.pw_uid)
                    os.umask(0o027)

            child_env["HOME"] = str(cwd) if cwd else account.pw_dir
        try:
            return subprocess.run(
                arguments, cwd=cwd, env=child_env, text=True,
                capture_output=True, timeout=timeout, check=True,
                preexec_fn=drop_privileges)
        except subprocess.TimeoutExpired as exc:
            raise RepositoryError("command_timeout") from exc
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "command failed")[-2000:]
            raise RepositoryError("command_failed", detail) from exc

    def _repository(self, name):
        value = self.repositories.get(name)
        if not isinstance(value, dict):
            raise RepositoryError("repository_not_allowed")
        return value

    def _manifest_path(self, identifier):
        if not isinstance(identifier, str) or not WORKSPACE.fullmatch(identifier):
            raise RepositoryError("invalid_workspace")
        return self.metadata / (identifier + ".json")

    def _manifest(self, identifier):
        self._verify_metadata()
        path = self._manifest_path(identifier)
        try:
            self._require_owned(path, directory=False)
            value = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise RepositoryError("workspace_not_found") from exc
        checkout = (self.root / identifier).resolve()
        git_dir = Path(value.get("git_dir", "")).resolve()
        if (checkout.parent != self.root or not checkout.is_dir() or
                checkout.is_symlink() or git_dir.parent != self.metadata or
                not git_dir.is_dir() or git_dir.is_symlink()):
            raise RepositoryError("invalid_workspace")
        self._require_owned(git_dir)
        return value, checkout

    def _save_manifest(self, value):
        self._verify_metadata()
        path = self._manifest_path(value["workspace"])
        temporary = self.metadata / (value["workspace"] + "." + uuid.uuid4().hex)
        temporary.write_text(json.dumps(value, sort_keys=True) + "\n")
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)

    @staticmethod
    def _share_tree(path):
        for current, folders, files in os.walk(path):
            folders[:] = [name for name in folders if name != ".git"]
            os.chmod(current, 0o2770)
            for name in folders:
                candidate = Path(current) / name
                if not candidate.is_symlink():
                    os.chmod(candidate, 0o2770)
            for name in files:
                candidate = Path(current) / name
                if candidate.name == ".git":
                    os.chmod(candidate, 0o640)
                    continue
                if candidate.is_symlink():
                    continue
                mode = candidate.stat().st_mode & 0o700
                os.chmod(candidate, 0o660 | (0o110 if mode & 0o100 else 0))

    @staticmethod
    def _share_git_metadata(path):
        for current, folders, files in os.walk(path):
            os.chmod(current, 0o2750)
            for name in folders:
                candidate = Path(current) / name
                if not candidate.is_symlink():
                    os.chmod(candidate, 0o2750)
            for name in files:
                candidate = Path(current) / name
                if not candidate.is_symlink():
                    os.chmod(candidate, 0o640)

    def checkout(self, repository, branch, label):
        self._verify_metadata()
        config = self._repository(repository)
        if not isinstance(branch, str) or not BRANCH.fullmatch(branch) or ".." in branch:
            raise RepositoryError("invalid_branch")
        if not isinstance(label, str) or not 1 <= len(label) <= 256:
            raise RepositoryError("invalid_label")
        identifier = "repo_" + uuid.uuid4().hex
        destination = self.root / identifier
        git_dir = self.metadata / (identifier + ".git")
        base = config.get("base_branch", "main")
        self._run(["git", "clone", "--separate-git-dir", str(git_dir),
                   "--single-branch", "--branch", base,
                   config["clone_url"], str(destination)],
                  env=self._push_env(config["clone_url"]))
        git_command = ["git", "--git-dir", str(git_dir),
                       "--work-tree", str(destination),
                       "-c", "core.hooksPath=/dev/null"]
        self._run([*git_command, "checkout", "-b", branch])
        revision = self._run([*git_command, "rev-parse", "HEAD"]).stdout.strip()
        manifest = {"schema": 1, "workspace": identifier,
                    "repository": repository, "branch": branch,
                    "base_branch": base, "base_revision": revision, "label": label,
                    "git_dir": str(git_dir)}
        self._save_manifest(manifest)
        self._share_git_metadata(git_dir)
        self._share_tree(destination)
        return {key: value for key, value in manifest.items() if key != "git_dir"} | {
            "path": str(destination)}

    def _push_env(self, remote):
        if not self.push_token:
            return {}
        token = base64.b64encode(("x-access-token:" + self.push_token).encode()).decode()
        return {"GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "http." + remote + ".extraHeader",
                "GIT_CONFIG_VALUE_0": "Authorization: Basic " + token}

    @staticmethod
    def _validation_env(checkout):
        return {"GIT_CONFIG_COUNT": "1",
                "GIT_CONFIG_KEY_0": "safe.directory",
                "GIT_CONFIG_VALUE_0": str(checkout)}

    def _worktree_identity(self, git_command, checkout):
        descriptor, raw_index = tempfile.mkstemp(
            prefix="validation-index-", dir=self.metadata)
        os.close(descriptor)
        index = Path(raw_index)
        index.unlink()
        environment = {"GIT_INDEX_FILE": str(index)}
        try:
            self._run([*git_command, "read-tree", "HEAD"], env=environment)
            self._run([*git_command, "add", "-A", "--", "."],
                      cwd=checkout, env=environment)
            return self._run(
                [*git_command, "write-tree"], env=environment).stdout.strip()
        finally:
            index.unlink(missing_ok=True)

    def _validate(self, config, checkout):
        validation = []
        for command in config.get("validation", []):
            if (not isinstance(command, list) or not command or
                    any(not isinstance(value, str) or not value
                        for value in command)):
                raise RepositoryError("invalid_configuration")
            completed = self._run(
                command, cwd=checkout, run_as=self.validation_user,
                env=self._validation_env(checkout))
            validation.append({"command": command, "status": "passed",
                               "output": (completed.stdout + completed.stderr)[-4000:]})
        return validation

    def propose(self, workspace, *, title, body):
        if not isinstance(title, str) or not 1 <= len(title) <= 256:
            raise RepositoryError("invalid_title")
        if not isinstance(body, str) or not 1 <= len(body) <= 32000:
            raise RepositoryError("invalid_body")
        manifest, checkout = self._manifest(workspace)
        config = self._repository(manifest["repository"])
        git_command = ["git", "--git-dir", manifest["git_dir"],
                       "--work-tree", str(checkout),
                       "-c", "core.hooksPath=/dev/null"]
        request_id = hashlib.sha256(json.dumps(
            [workspace, title, body], separators=(",", ":")).encode()).hexdigest()
        progress = manifest.get("proposal")
        if progress and progress.get("request_id") != request_id:
            raise RepositoryError("proposal_in_progress")
        if not progress:
            tree = self._worktree_identity(git_command, checkout)
            validation = self._validate(config, checkout)
            if self._worktree_identity(git_command, checkout) != tree:
                raise RepositoryError("workspace_changed_during_validation")
            changed = self._run(
                [*git_command, "status", "--porcelain"]).stdout.splitlines()
            if not changed:
                raise RepositoryError("no_changes")
            progress = {"request_id": request_id, "state": "validated",
                        "changes": changed, "validation": validation,
                        "tree": tree}
            manifest["proposal"] = progress
            self._save_manifest(manifest)
        else:
            validation = progress["validation"]
            changed = progress["changes"]

        if "tree" not in progress:
            tree = self._worktree_identity(git_command, checkout)
            validation = self._validate(config, checkout)
            if self._worktree_identity(git_command, checkout) != tree:
                raise RepositoryError("workspace_changed_during_validation")
            progress["validation"] = validation
            progress["tree"] = tree
            self._save_manifest(manifest)

        if progress["state"] == "validated":
            if self._worktree_identity(git_command, checkout) != progress["tree"]:
                raise RepositoryError("workspace_changed_after_validation")
            head = self._run(
                [*git_command, "rev-parse", "HEAD"]).stdout.strip()
            if head == manifest["base_revision"]:
                self._run([*git_command, "add", "-A", "--", "."], cwd=checkout)
                staged = self._run([*git_command, "write-tree"]).stdout.strip()
                if staged != progress["tree"]:
                    raise RepositoryError("workspace_changed_after_validation")
                self._run([*git_command, "-c", "user.name=Zig CVE investigator",
                           "-c", "user.email=zig-cve@users.noreply.github.com",
                           "commit", "-m", title])
                head = self._run(
                    [*git_command, "rev-parse", "HEAD"]).stdout.strip()
            else:
                parent = self._run(
                    [*git_command, "rev-parse", "HEAD^"]).stdout.strip()
                committed_tree = self._run(
                    [*git_command, "rev-parse", "HEAD^{tree}"]).stdout.strip()
                if (parent != manifest["base_revision"] or
                        committed_tree != progress["tree"]):
                    raise RepositoryError("workspace_changed_after_validation")
            if self._worktree_identity(git_command, checkout) != progress["tree"]:
                raise RepositoryError("workspace_changed_after_validation")
            progress.update({"state": "committed", "commit": head})
            self._save_manifest(manifest)

        head = self._run([*git_command, "rev-parse", "HEAD"]).stdout.strip()
        dirty = self._run([*git_command, "status", "--porcelain"]).stdout.strip()
        if head != progress["commit"] or dirty:
            raise RepositoryError("workspace_changed_after_commit")
        remote = config["clone_url"]
        if progress["state"] == "committed":
            self._run([*git_command, "push", remote,
                       "HEAD:refs/heads/" + manifest["branch"]],
                      env=self._push_env(remote))
            progress["state"] = "pushed"
            self._save_manifest(manifest)

        pull = progress.get("pull_request")
        if not pull:
            pull = self.provider.find_pull_request(
                config["provider_repository"], manifest["branch"],
                manifest["base_branch"])
            if not pull:
                pull = self.provider.create_pull_request(
                    config["provider_repository"], manifest["branch"],
                    manifest["base_branch"], title, body)
            progress.update({"state": "proposed", "pull_request": pull})
            self._save_manifest(manifest)
        return {"status": "proposed", "workspace": workspace,
                "repository": manifest["repository"], "branch": manifest["branch"],
                "base_revision": manifest["base_revision"], "pr": pull["url"],
                "pr_number": pull["number"], "changes": changed,
                "validation": validation}


def call_socket(path, payload):
    raw = json.dumps(payload, separators=(",", ":")).encode() + b"\n"
    if len(raw) > 128 * 1024:
        raise RepositoryError("request_too_large")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(1250)
        client.connect(path)
        client.sendall(raw)
        stream = client.makefile("rb")
        result = json.loads(stream.readline())
    if result.get("status") == "error":
        raise RepositoryError(result.get("error", "broker_error"), result.get("detail", ""))
    return result


def serve(path, broker):
    socket_path = Path(path)
    socket_path.unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(str(socket_path))
        os.chmod(socket_path, 0o660)
        server.listen(8)
        while True:
            connection, _ = server.accept()
            with connection:
                try:
                    line = connection.makefile("rb").readline(128 * 1024 + 1)
                    if not line or len(line) > 128 * 1024:
                        raise RepositoryError("request_too_large")
                    payload = json.loads(line)
                    action = payload.pop("action")
                    if action == "checkout":
                        result = broker.checkout(**payload)
                    elif action == "propose":
                        result = broker.propose(**payload)
                    else:
                        raise RepositoryError("operation_not_allowed")
                except RepositoryError as exc:
                    result = {"status": "error", "error": exc.code,
                              "detail": exc.detail}
                except (KeyError, TypeError, ValueError, json.JSONDecodeError):
                    result = {"status": "error", "error": "invalid_request"}
                connection.sendall(json.dumps(result, separators=(",", ":")).encode() + b"\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", default="/run/homelab-repository/broker.sock")
    parser.add_argument("--config", default="/etc/homelab-investigator/repositories.json")
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("serve")
    checkout = sub.add_parser("checkout")
    checkout.add_argument("repository")
    checkout.add_argument("branch")
    checkout.add_argument("label")
    propose = sub.add_parser("propose")
    propose.add_argument("workspace")
    propose.add_argument("title")
    propose.add_argument("body")
    args = parser.parse_args()
    if args.action == "serve":
        config = json.loads(Path(args.config).read_text())
        credential = Path(os.environ["CREDENTIALS_DIRECTORY"], "github-token")
        token = credential.read_text().strip()
        serve(args.socket, RepositoryBroker(config, GitHubProvider(token), token))
        return 0
    payload = vars(args).copy()
    payload.pop("socket")
    payload.pop("config")
    result = call_socket(args.socket, payload)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RepositoryError as exc:
        print(json.dumps({"status": "error", "error": exc.code,
                          "detail": exc.detail}))
        raise SystemExit(1)
