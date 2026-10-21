#!/usr/bin/env python3
"""Read-only thin-pool capacity and monitoring checks."""
import argparse
from decimal import Decimal, ROUND_CEILING
import json
import re
import subprocess
import sys


def problems(pool, group, *, data_limit, metadata_limit, extend_percent, reserve_bytes):
    data = Decimal(pool['data_percent'])
    metadata = Decimal(pool['metadata_percent'])
    size = Decimal(pool['lv_size'])
    extent = Decimal(group['vg_extent_size'])
    free = Decimal(group['vg_free'])
    if not all(value.is_finite() for value in (data, metadata, size, extent, free)):
        raise ValueError('non-finite LVM measurements')
    if not 0 <= data <= 100 or not 0 <= metadata <= 100 or size <= 0 or extent <= 0 or free < 0:
        raise ValueError('invalid LVM measurements')
    extension = (size * extend_percent / 100 / extent).to_integral_value(rounding=ROUND_CEILING) * extent
    required = extension + reserve_bytes
    failures = []
    if data >= data_limit:
        failures.append(f'thin-pool data usage is {data}%; threshold is {data_limit}%')
    if metadata >= metadata_limit:
        failures.append(f'thin-pool metadata usage is {metadata}%; threshold is {metadata_limit}%')
    if free < required:
        failures.append(f'VG free space is {int(free)} bytes; next extension plus reserve needs {int(required)}')
    if pool.get('seg_monitor', '').strip() != 'monitored':
        failures.append('thin pool is not monitored by LVM')
    if pool.get('lv_profile', '').strip() != 'homelab-thinpool':
        failures.append('thin pool is missing the managed extension profile')
    return failures


def report(argv, section):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=8, check=True)
    rows = json.loads(result.stdout)['report'][0][section]
    if len(rows) != 1:
        raise ValueError('expected one LVM object')
    return rows[0]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--pool', required=True)
    parser.add_argument('--data-limit', type=Decimal, required=True)
    parser.add_argument('--metadata-limit', type=Decimal, required=True)
    parser.add_argument('--extend-percent', type=Decimal, required=True)
    parser.add_argument('--reserve-bytes', type=int, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.+-]+/[A-Za-z0-9_.+-]+', args.pool):
        parser.error('expected VG/LV')
    if not (0 < args.data_limit <= 100 and 0 < args.metadata_limit <= 100
            and 0 < args.extend_percent <= 100 and args.reserve_bytes >= 0):
        parser.error('invalid capacity limits')
    common = ['--reportformat', 'json', '--units', 'b', '--nosuffix', '--nohints']
    try:
        pool = report(['lvs', *common, '-o', 'lv_size,data_percent,metadata_percent,seg_monitor,lv_profile', args.pool], 'lv')
        group = report(['vgs', *common, '-o', 'vg_free,vg_extent_size', args.pool.split('/')[0]], 'vg')
        failures = problems(pool, group, data_limit=args.data_limit, metadata_limit=args.metadata_limit,
                            extend_percent=args.extend_percent, reserve_bytes=args.reserve_bytes)
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError, ArithmeticError) as exc:
        print(f'Cannot inspect thin-pool health: {type(exc).__name__}', file=sys.stderr)
        return 1
    if failures:
        print('; '.join(failures), file=sys.stderr)
        return 1
    print('Thin-pool usage and VG headroom satisfy the managed extension policy')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
