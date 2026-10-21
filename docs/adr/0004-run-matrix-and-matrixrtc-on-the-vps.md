# Run Matrix and MatrixRTC on the VPS

Tuwunel and MatrixRTC run on the VPS so client, federation, signaling, and
media traffic do not depend on the home connection. Traefik terminates the
Matrix HTTP routes, while LiveKit exposes only its required direct media ports.
Pangolin browser authentication stays out of these paths because Matrix clients
cannot complete an interactive gateway login.
