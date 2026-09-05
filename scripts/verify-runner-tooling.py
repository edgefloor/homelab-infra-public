#!/usr/bin/python3
"""Download and verify Phase 0 runner inputs. Never installs them."""
import argparse, hashlib, json, os, pathlib, re, subprocess, sys, tempfile, urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs/phase0/tool-versions.yml"

def fail(message):
    print(f"FAIL {message}", file=sys.stderr)
    raise SystemExit(1)

def run(args, *, stdout=True):
    return subprocess.run(args, check=True, text=True,
                          stdout=subprocess.PIPE if stdout else subprocess.DEVNULL,
                          stderr=subprocess.PIPE).stdout if stdout else ""

def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""): h.update(block)
    return h.hexdigest()

def packages_stanzas(index):
    data = run(["/usr/lib/apt/apt-helper", "cat-file", str(index)])
    for raw in data.split("\n\n"):
        fields = {}
        for line in raw.splitlines():
            if ": " in line:
                key, value = line.split(": ", 1); fields[key] = value
        if fields: yield fields

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    out = pathlib.Path(args.output_dir).resolve()
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(out.iterdir()): fail("output directory must be empty")
    manifest = json.loads(MANIFEST.read_text())
    if run(["dpkg", "--print-architecture"]).strip() != "amd64": fail("architecture is not amd64")
    os_release = pathlib.Path("/etc/os-release").read_text()
    if "VERSION_ID=\"13\"" not in os_release and "VERSION_ID=13" not in os_release: fail("host is not Debian 13")
    print(f"FACT manifest_sha256={digest(MANIFEST)}")

    allowed_origins = tuple(manifest["trust_boundary"]["allowed_https_origins"])
    allowed_suites = set(manifest["trust_boundary"]["allowed_suites"])
    run(["apt-get", "update"], stdout=False)  # fail-closed InRelease authentication
    targets = run(["apt-get", "indextargets", "--format", "$(FILENAME)\t$(URI)\t$(ARCHITECTURE)", "Created-By: Packages"])
    indexes = []
    for line in targets.splitlines():
        filename, uri, arch = line.split("\t")
        suite_match = re.search(r"/dists/([^/]+)/", uri)
        if not suite_match: fail("configured Packages URI has no suite")
        suite = suite_match.group(1)
        if suite not in allowed_suites: fail(f"configured Packages suite rejected: {suite}")
        if arch not in {"amd64", "all"}: fail(f"configured Packages architecture rejected: {arch}")
        if not uri.startswith(allowed_origins) or urllib.parse.urlparse(uri).scheme != "https": fail("configured Packages origin rejected")
        origin = next(origin for origin in allowed_origins if uri.startswith(origin))
        indexes.append((pathlib.Path(filename), origin, suite, arch))
    if not indexes: fail("no authenticated allowed Packages indexes")

    for package, version in manifest["debian_packages"]["packages"].items():
        matches = []
        for index, base_uri, suite, arch in indexes:
            for fields in packages_stanzas(index):
                if fields.get("Package") == package and fields.get("Version") == version:
                    if not re.fullmatch(r"[0-9a-f]{64}", fields.get("SHA256", "")): fail(f"{package} lacks SHA256")
                    rel = fields.get("Filename", "")
                    url = urllib.parse.urljoin(base_uri, rel)
                    if not url.startswith(allowed_origins) or urllib.parse.urlparse(url).scheme != "https": fail(f"{package} URL rejected")
                    matches.append((url, fields["SHA256"], suite, fields.get("Architecture")))
        unique = set(matches)
        if len(unique) != 1: fail(f"{package} exact authenticated resolution count={len(unique)}")
        url, expected, suite, arch = unique.pop()
        if arch not in {"amd64", "all"}: fail(f"{package} package architecture rejected")
        destination = out / pathlib.PurePosixPath(urllib.parse.urlparse(url).path).name
        run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2", "--output", str(destination), url])
        actual = digest(destination)
        if actual != expected: fail(f"{package} checksum mismatch")
        print(f"FACT package={package} version={version} arch={arch} suite={suite} url={url} authenticated_sha256={expected} calculated_sha256={actual} result=matched")

    for name, item in manifest["upstream_artifacts"].items():
        url = item["url"]
        if urllib.parse.urlparse(url).scheme != "https" or "/releases/download/" not in url: fail(f"{name} URL rejected")
        destination = out / pathlib.PurePosixPath(urllib.parse.urlparse(url).path).name
        run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2", "--output", str(destination), url])
        actual = digest(destination)
        if actual != item["sha256"]: fail(f"{name} checksum mismatch")
        digest_label = "reviewed_calculated_sha256" if item.get("sha256_kind") == "reviewed_calculated" else "publisher_sha256"
        print(f"FACT artifact={name} version={item['version']} arch={item['architecture']} url={url} {digest_label}={item['sha256']} calculated_sha256={actual} result=matched")
        if "checksum_manifest_url" in item:
            check = out / (destination.name + ".checksums")
            run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https", "--tlsv1.2", "--output", str(check), item["checksum_manifest_url"]])
            check_actual = digest(check)
            if check_actual != item["checksum_manifest_sha256"]: fail(f"{name} checksum manifest mismatch")
            expected_line = f"{item['sha256']}  {destination.name}"
            if expected_line not in check.read_text(errors="strict").splitlines(): fail(f"{name} absent from checksum manifest")
            provenance = item.get("checksum_manifest_sha256_kind", "publisher_sha256")
            print(f"FACT checksum_manifest={name} url={item['checksum_manifest_url']} provenance={provenance} selected_sha256={item['checksum_manifest_sha256']} calculated_sha256={check_actual} entry_digest={item['sha256']} entry_result=matched")
    print("FACT overall_result=matched")

if __name__ == "__main__":
    try: main()
    except (OSError, subprocess.CalledProcessError, ValueError, KeyError, json.JSONDecodeError) as error:
        fail(type(error).__name__)
