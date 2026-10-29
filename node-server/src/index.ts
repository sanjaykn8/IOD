import express from "express";
import cors from "cors";
import { config } from "./config";
import { router } from "./api/routes";
import { rust } from "./services/rustClient";

const app = express();
app.use(cors());
// Only the cover-upload route (browser webcam frame / uploaded PNG) may carry a large body; everything else keeps the small default.
const smallJson = express.json();
const coverJson = express.json({ limit: "14mb" });
app.use((req, res, next) => (req.path === "/api/stego/cover/upload" ? coverJson(req, res, next) : smallJson(req, res, next)));

app.use("/api", router);

// ---------------------------------------------------------------------
// Server-Sent Events: the browser gets a real SSE stream from Node, even
// though Node itself talks to Rust via polling. See
// rust-core/src/api/server.rs module docs for why Rust does not expose
// a native WebSocket/SSE channel in this sandbox (old rustc -> no
// current axum/tokio). This keeps the browser-facing contract
// "real-time updates via SSE" true regardless of that internal detail.
// ---------------------------------------------------------------------
app.get("/api/events/stream", async (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
  });
  res.write("\n");

  let cursor = 0;
  let closed = false;
  req.on("close", () => {
    closed = true;
  });

  while (!closed) {
    try {
      const r = await rust.get(`/api/events?since=${cursor}`);
      if (r.ok && Array.isArray(r.body.events)) {
        for (const ev of r.body.events) {
          res.write(`data: ${JSON.stringify(ev)}\n\n`);
        }
        cursor = r.body.next_cursor ?? cursor;
      }
    } catch {
      // Rust core not reachable yet — keep the stream open and retry.
    }
    await new Promise((resolve) => setTimeout(resolve, config.eventPollIntervalMs));
  }
});

app.get("/api/health", async (_req, res) => {
  const rustHealth = await rust.get("/api/state");
  res.json({
    node: "ok",
    rust_core_reachable: rustHealth.ok,
  });
});

app.listen(config.port, () => {
  // eslint-disable-next-line no-console
  console.log(`iod-node-gateway listening on http://127.0.0.1:${config.port}`);
  console.log(`  -> proxying Rust core at ${config.rustBaseUrl}`);
  console.log(`  -> proxying Python RAG service at ${config.pythonBaseUrl}`);
});
