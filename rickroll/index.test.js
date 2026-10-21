import { expect, test } from "bun:test";

const html = await Bun.file(new URL("./index.html", import.meta.url)).text();

test("preloads a browser-safe muted autoplay embed", () => {
  expect(html).toContain("autoplay=1");
  expect(html).toContain("mute=1");
  expect(html).toContain("enablejsapi=1");
});

test("the reveal gesture asks YouTube to unmute and play", () => {
  expect(html).toContain('"unMute"');
  expect(html).toContain('"playVideo"');
});
