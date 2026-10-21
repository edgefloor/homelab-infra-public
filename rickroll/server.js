const host = process.env.HOST || "127.0.0.1";
const port = Number(process.env.PORT || 3000);
const page = Bun.file(new URL("./index.html", import.meta.url));

export function fallbackResponse(_request) {
  return new Response(page, {
    status: 404,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

if (import.meta.main) {
  Bun.serve({
    hostname: host,
    port,
    fetch: fallbackResponse,
  });

  console.log(`Rickroll ready at http://${host}:${port}`);
}
