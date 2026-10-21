# Keep access and application authentication separate

Pangolin decides who may reach a gateway route. The application then creates
its own session through native OIDC, a narrowly trusted identity header, or its
local login. Treating the gateway session as a universal application session
would require every service to trust proxy identity in the same way and would
turn one header mistake into account impersonation.
