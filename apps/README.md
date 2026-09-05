# Application manifests

Each YAML file describes one managed application. It records the pinned
release, runtime, routes, health check, and state that must survive an upgrade.
Host topology belongs in [`../inventory/`](../inventory/).

Validate the manifests with:

```sh
uv run python scripts/validate_app_manifests.py
```

The common fields form the repository contract. Service-specific sections such
as `authentication`, `agents`, and `notifications` may add facts that do not
apply to every application.
