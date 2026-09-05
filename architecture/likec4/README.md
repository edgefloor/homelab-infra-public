# Architecture diagrams

The LikeC4 model shows the current system. It is a readable projection of the
inventories, not another source of truth.

## Open the diagrams

From the repository root:

```sh
bun install
bun run diagrams:dev
```

The views cover the whole homelab, ingress and split DNS, identity and roles,
observability, the physical deployment, and the main sign-in flows.

## Check the model

```sh
bun run diagrams:validate
bun run diagrams:build
```

The build writes `architecture/likec4/dist/`. Update the model when a current
inventory changes. Routing still comes from `inventory/routes.yml`.
