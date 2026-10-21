import { expect, test } from "bun:test";

import { fallbackResponse } from "./server.js";

for (const path of ["/", "/index.html", "/missing/path"]) {
  test(`serves the supplied page with status 404 at ${path}`, async () => {
    const response = fallbackResponse(new Request(`http://fallback.test${path}`));

    expect(response.status).toBe(404);
    expect(response.headers.get("Content-Type")).toBe("text/html; charset=utf-8");
    expect(await response.text()).toContain("Definitely Not a Rickroll");
  });
}
