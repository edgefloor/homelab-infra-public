#!/usr/bin/env python3
"""Verify a native candidate without executing it or changing a service."""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def assess(report, package, analyzer, advisory):
    results = [r for r in report.get('Results', []) if r.get('Type') == analyzer]
    packages = [p for result in results for p in result.get('Packages', [])]
    present = [p for p in packages if p.get('Name') == package]
    matches = [v for result in results for v in result.get('Vulnerabilities', []) if v.get('VulnerabilityID') == advisory]
    return {'status': 'affected' if matches else ('verified_for_advisory' if present else 'unknown'),
            'analyzer': analyzer, 'package': package, 'package_versions': sorted({p['Version'] for p in present}),
            'package_count': len(packages), 'matches': matches,
            'limitations': ['Advisory verification does not establish application compatibility, build provenance, recovery, or overall safety.']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--candidate', type=Path, required=True)
    parser.add_argument('--current', type=Path, required=True)
    parser.add_argument('--package', required=True)
    parser.add_argument('--analyzer', choices=['gobinary', 'rustbinary', 'dotnet-core', 'node-pkg', 'python-pkg'], required=True)
    parser.add_argument('--advisory', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'(CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+|GO-\d{4}-\d+)', args.advisory):
        raise ValueError('invalid advisory')
    for path in (args.candidate, args.current):
        if not path.is_absolute() or not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
            raise ValueError('candidate and current artifact must be bounded regular files')
    before = {str(p): digest(p) for p in (args.candidate, args.current)}
    with tempfile.TemporaryDirectory(prefix='homelab-candidate-') as temp:
        output = Path(temp) / 'report.json'
        subprocess.run(['/usr/local/bin/trivy', 'rootfs', '--scanners', 'vuln', '--pkg-types', 'library',
                        '--list-all-pkgs', '--format', 'json', '--output', str(output), str(args.candidate)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=900, check=True)
        report = json.loads(output.read_text())
    if before != {str(p): digest(p) for p in (args.candidate, args.current)}:
        raise ValueError('artifact changed during candidate verification')
    result = assess(report, args.package, args.analyzer, args.advisory)
    result.update(schema=1, observed_at=datetime.now(UTC).isoformat(), advisory=args.advisory,
                  candidate_sha256=before[str(args.candidate)], current_sha256=before[str(args.current)])
    args.output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    args.output.chmod(0o600)
    print(json.dumps({k: result[k] for k in ('status', 'advisory', 'package_count', 'candidate_sha256')}))


if __name__ == '__main__':
    main()
