#!/usr/bin/env python3
"""Add a profile-local onboarding switch to the pinned native Hermes gateway.

Defaults preserve personal Hermes behaviour. Fail closed if upstream changes the
injection points, rather than silently restoring setup messages for Zig.
"""
import ast
import sys
from pathlib import Path

ANCHOR = (
    '        from gateway.run import _hermes_home, _home_target_env_var, '
    '_load_gateway_config\n'
)
GUARD = (
    "        if not _load_gateway_config().get('onboarding', {}).get('enabled', True):\n"
    '            return\n'
)


def patched(source):
    replacement = ANCHOR + GUARD
    if source.count(replacement) == 1:
        ast.parse(source)
        return source
    if source.count(ANCHOR) != 1:
        raise ValueError('Hermes onboarding injection point changed; review the gateway patch')
    source = source.replace(ANCHOR, replacement, 1)
    ast.parse(source)
    return source


if __name__ == '__main__':
    path = Path(sys.argv[1])
    before = path.read_text()
    after = patched(before)
    if before != after:
        path.write_text(after)
        print('updated onboarding switch')
    else:
        print('onboarding switch already installed')
