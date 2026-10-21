# Legacy Mac exposure recovery

This is the retired Python proof of concept. The installed command is now
`~/.local/bin/expose-legacy`. Its bytes match `expose.py` in this directory.
The generic `~/.local/bin/expose` entrypoint has been removed to avoid confusing
this SSH-based implementation with the separate Go Alagut project.

The Go implementation cannot yet replace live exposure operations. This copy
remains available for deliberate legacy recovery. It is not an Alagut transport
fallback. Do not point Alagut at its state or credentials.

The historical installer is retained as `install_mac_exposure_proxy.py.retired`
for reference. It is not a supported installer. It would overwrite configuration
and restart Caddy, so do not run it during the migration.

The Caddy LaunchAgent runs Caddy directly and does not import these Python files.
Its configuration, state, logs, credentials, and running process remain in place.
The user removed the last exposure, `learning`, before this retirement.

## Inspect the retained state

Run `expose-legacy list` to read local exposure state. This operation does not
call Pangolin or read the API key. Other legacy operations still use the old
credential and SSH transport. They are not part of the new setup work.

## Restore the old command name

Only restore it if `~/.local/bin/expose` is absent and no replacement is installed:

```sh
	test ! -e "$HOME/.local/bin/expose" &&
		ln "$HOME/.local/bin/expose-legacy" "$HOME/.local/bin/expose"
```

The link operation refuses an existing destination. It does not restart Caddy or
change any credential. Remove only that restored link when retiring it again.

## Check the frozen implementation

```sh
	python3 -m unittest discover -s scripts -p 'test_legacy_mac_exposure.py'
```

These tests use temporary files and mocked APIs. They do not validate live
Pangolin behavior or authorize live exposure changes.
