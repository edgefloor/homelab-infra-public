#!/usr/bin/env python3
"""Create a dedicated application database using PostgreSQL's native CLI."""

from pathlib import Path
import subprocess
import sys

password = Path('/etc/dependency-track/database-password').read_text().strip()
quoted = "'" + password.replace("'", "''") + "'"
sql = r"""
SELECT 'CREATE ROLE dtrack LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='dtrack')\gexec
ALTER ROLE dtrack PASSWORD %s;
SELECT 'CREATE DATABASE dtrack OWNER dtrack' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='dtrack')\gexec
""" % quoted
# Credentials travel through stdin, never argv or logs.
result = subprocess.run(
    ['runuser', '-u', 'postgres', '--', 'psql', '-X', '-v', 'ON_ERROR_STOP=1',
     '-h', '/var/run/postgresql', '-p', sys.argv[1], '-d', 'postgres'],
    input=sql, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
if result.returncode:
    sys.exit('Dependency-Track database configuration failed')
