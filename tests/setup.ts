import { afterEach } from "vitest";

// axe-core probes canvas text metrics for its contrast checks. jsdom does not
// implement a real canvas, so provide the smallest deterministic test stub.
if (typeof HTMLCanvasElement !== "undefined") {
  HTMLCanvasElement.prototype.getContext = (() => ({
    measureText: () => ({ width: 0 }),
  })) as unknown as typeof HTMLCanvasElement.prototype.getContext;
}

afterEach(() => {
  document.body.innerHTML = "";
  window.localStorage.clear();
});
