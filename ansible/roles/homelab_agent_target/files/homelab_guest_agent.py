#!/usr/bin/env python3
"""Route bounded agent requests only to explicitly enrolled external LXCs."""
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path


def validate(request, config):
    if not isinstance(request, dict) or set(request) != {'guest', 'command', 'input'}:
        raise ValueError('invalid guest request')
    allowed = {guest['id'] for guest in config.get('external_guests', [])}
    command = request['command']
    operation_allowed = isinstance(command, list) and (command in [['evidence'], ['coverage'], ['defense'], ['snapshot']] or
        (len(command) == 2 and command[0] == 'snapshot' and isinstance(command[1], str) and re.fullmatch(r'[A-Za-z0-9_.@-]{1,128}', command[1])))
    if type(request['guest']) is not int or request['guest'] not in allowed or not operation_allowed:
        raise ValueError('guest or operation is not enrolled')
    if not isinstance(request['input'], str) or len(request['input'].encode()) > 128 * 1024:
        raise ValueError('guest request exceeds limit')
    return ['pct', 'exec', str(request['guest']), '--', '/usr/bin/env',
            'SSH_ORIGINAL_COMMAND=' + shlex.join(command), '/usr/local/libexec/homelab-agent-remote']


def main():
    raw = sys.stdin.buffer.read(256 * 1024 + 1)
    if len(raw) > 256 * 1024:
        raise ValueError('guest request exceeds limit')
    request = json.loads(raw)
    config = json.loads(Path('/etc/homelab-update-monitor/deployments.json').read_text())
    argv = validate(request, config)
    result = subprocess.run(argv, input=request['input'], capture_output=True, text=True, timeout=650)
    if len(result.stdout.encode()) > 256 * 1024:
        raise ValueError('guest result exceeds limit')
    sys.stdout.write(result.stdout)
    return result.returncode


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print(json.dumps({'ok': False, 'error': 'guest access rejected or failed'}))
        raise SystemExit(1)
