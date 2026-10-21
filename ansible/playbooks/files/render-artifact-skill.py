"""Migrate only the three reviewed artifact-interface blocks in a shared skill."""
import json
from pathlib import Path
import sys


def render(source: bytes, replacements: list[dict]) -> bytes:
    text = source.decode('utf-8')
    for change in replacements:
        before, after = change['before'], change['after']
        if not before or not after or before == after:
            raise ValueError('Invalid artifact documentation migration')
        counts = (text.count(before), text.count(after))
        if counts == (1, 0):
            text = text.replace(before, after, 1)
        elif counts != (0, 1):
            raise ValueError('Shared skill has an unknown or ambiguous artifact block: ' + change['name'])
    return text.encode('utf-8')


if __name__ == '__main__':
    original, destination = map(Path, sys.argv[1:3])
    updated = render(original.read_bytes(), json.loads(sys.argv[3]))
    with destination.open('xb') as output:
        output.write(updated)
