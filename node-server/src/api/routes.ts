import { Router, Request, Response } from "express";
import { rust, RustRawResponse } from "../services/rustClient";
import { python } from "../services/pythonClient";

export const router = Router();

function relay(res: Response, r: { status: number; body: any }) {
  res.status(r.status).json(r.body);
}

// ---------------------------------------------------------------------
// Rust-core-backed endpoints: simulation control, drones, groups,
// authentication, group-key, secure messaging, trace manager, events.
// Every one of these is a direct, unmodified proxy to the Rust HTTP API
// — Node adds no cryptographic or protocol logic of its own, per the
// "Rust is the security-critical implementation" requirement.
// ---------------------------------------------------------------------

router.post("/reset", async (_req, res) => relay(res, await rust.post("/api/reset")));
router.get("/state", async (_req, res) => relay(res, await rust.get("/api/state")));

router.post("/groups", async (req, res) => relay(res, await rust.post("/api/groups", req.body)));
router.get("/groups", async (_req, res) => relay(res, await rust.get("/api/groups")));
router.get("/groups/:groupId", async (req, res) => relay(res, await rust.get(`/api/groups/${encodeURIComponent(req.params.groupId)}`)));

router.post("/drones", async (req, res) => relay(res, await rust.post("/api/drones", req.body)));
router.get("/drones", async (_req, res) => relay(res, await rust.get("/api/drones")));
router.get("/drones/:id", async (req, res) => relay(res, await rust.get(`/api/drones/${encodeURIComponent(req.params.id)}`)));
router.post("/drones/:id/register", async (req, res) => relay(res, await rust.post(`/api/drones/${encodeURIComponent(req.params.id)}/register`, req.body)));
router.post("/drones/:id/revoke", async (req, res) => relay(res, await rust.post(`/api/drones/${encodeURIComponent(req.params.id)}/revoke`)));
router.post("/drones/:id/reactivate", async (req, res) => relay(res, await rust.post(`/api/drones/${encodeURIComponent(req.params.id)}/reactivate`)));
router.post("/drones/:id/move", async (req, res) => relay(res, await rust.post(`/api/drones/${encodeURIComponent(req.params.id)}/move`, req.body)));

router.post("/authenticate", async (req, res) => relay(res, await rust.post("/api/authenticate", req.body)));
router.post("/group-key", async (req, res) => relay(res, await rust.post("/api/group-key", req.body)));
router.post("/secure-message", async (req, res) => relay(res, await rust.post("/api/secure-message", req.body)));

router.post("/trace/flag", async (req, res) => relay(res, await rust.post("/api/trace/flag", req.body)));
// Administrator authority comes ONLY from the X-Admin-Token header, which the
// Rust core verifies against IOD_ADMIN_TOKEN. Any role claim in the body is ignored.
router.post("/trace/request", async (req, res) => {
  const tok = req.header("x-admin-token");
  relay(res, await rust.post("/api/trace/request", req.body, tok ? { "X-Admin-Token": tok } : undefined));
});
router.get("/trace", async (_req, res) => relay(res, await rust.get("/api/trace")));
router.get("/events/history", async (req, res) => {
  const limit = req.query.limit ? `?limit=${encodeURIComponent(String(req.query.limit))}` : "";
  relay(res, await rust.get(`/api/events/history${limit}`));
});

// ---------------------------------------------------------------------
// Python-RAG-backed endpoints.
// ---------------------------------------------------------------------

router.post("/rag/contribute", async (req, res) => relay(res, await python.post("/rag/contribute", req.body)));
router.post("/rag/run", async (req, res) => relay(res, await python.post("/rag/run", req.body)));
router.get("/rag/state", async (_req, res) => relay(res, await python.get("/rag/state")));
router.post("/rag/reset", async (_req, res) => relay(res, await python.post("/rag/reset")));

// ---------------------------------------------------------------------
// Steganography Lab: THIN relay onto the Rust `/api/stego/*` API (see
// docs/stego-implementation-note.md section 4.2). No security logic, no
// policy, no keys: bodies and status codes pass through unchanged. The only
// checks here are request-shape guards on the artifact path (so a malformed
// id never reaches Rust) and a structured 502 when Rust is unreachable.
// ---------------------------------------------------------------------

const STEGO_UNAVAILABLE = {
  ok: false,
  error: { code: "STEGO_BACKEND_UNAVAILABLE", message: "Rust core is unreachable from the gateway", stage: "gateway" },
  stages: [],
};

function guard(fn: (req: Request, res: Response) => Promise<void>) {
  return async (req: Request, res: Response) => {
    try {
      await fn(req, res);
    } catch {
      if (!res.headersSent) res.status(502).json(STEGO_UNAVAILABLE);
    }
  };
}

function rawQuery(req: Request): string {
  const i = req.originalUrl.indexOf("?");
  return i >= 0 ? req.originalUrl.slice(i) : "";
}

function relayRaw(res: Response, r: RustRawResponse, extraHeaders?: Record<string, string>) {
  res.status(r.status).set("Content-Type", r.contentType);
  for (const [k, v] of Object.entries(extraHeaders ?? {})) res.set(k, v);
  res.send(r.body);
}

const stego = (path: string) => `/api/stego${path}`;

router.get("/stego/status", guard(async (_req, res) => relay(res, await rust.get(stego("/status")))));
router.post("/stego/cover/upload", guard(async (req, res) => relay(res, await rust.post(stego("/cover/upload"), req.body ?? {}))));
router.post("/stego/camera/probe", guard(async (req, res) => relay(res, await rust.post(stego("/camera/probe"), req.body ?? {}))));
router.post("/stego/analyze", guard(async (req, res) => relay(res, await rust.post(stego("/analyze"), req.body ?? {}))));
router.post("/stego/message", guard(async (req, res) => relay(res, await rust.post(stego("/message"), req.body ?? {}))));
router.post("/stego/send", guard(async (req, res) => relay(res, await rust.post(stego("/send"), req.body ?? {}))));
router.post("/stego/receive", guard(async (req, res) => relay(res, await rust.post(stego("/receive"), req.body ?? {}))));
router.post("/stego/benchmark", guard(async (req, res) => relay(res, await rust.post(stego("/benchmark"), req.body ?? {}))));
router.get("/stego/events", guard(async (req, res) => relay(res, await rust.get(stego(`/events${rawQuery(req)}`)))));
router.get(
  "/stego/report",
  guard(async (req, res) => {
    if (req.query.format === "csv") {
      const r = await rust.getRaw(stego(`/report${rawQuery(req)}`));
      relayRaw(res, r, r.status === 200 ? { "Content-Disposition": 'attachment; filename="stego-report.csv"' } : undefined);
    } else {
      relay(res, await rust.get(stego(`/report${rawQuery(req)}`)));
    }
  }),
);
router.get(
  "/stego/artifacts/:id/:kind",
  guard(async (req, res) => {
    const { id, kind } = req.params;
    if (!/^[0-9a-f]{32}$/.test(id) || (kind !== "stego" && kind !== "cover")) {
      res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: "invalid artifact id or kind", stage: "gateway" } });
      return;
    }
    const r = await rust.getRaw(stego(`/artifacts/${id}/${kind}`));
    relayRaw(res, r, { "X-Content-Type-Options": "nosniff", ...(r.status === 200 ? { "Cache-Control": "private, max-age=3600" } : {}) });
  }),
);

// ---------------------------------------------------------------------
// Algorithm Learning workbench (EDUCATIONAL): thin relay onto Rust `/api/learn/*`.
// Separate namespace from `/api/stego/*`; nothing here reaches the UAV transport.
// ---------------------------------------------------------------------
const learn = (path: string) => `/api/learn${path}`;
const LEARN_ALGS = new Set(["lsb_replacement", "lsb_matching", "pvd", "edge_adaptive_lsb", "dct", "dwt", "dct_svd", "hugo", "wow", "s_uniward"]);
router.get("/learn/registry", guard(async (_req, res) => relay(res, await rust.get(learn("/registry")))));
router.get(
  "/learn/walkthrough/:alg",
  guard(async (req, res) => {
    const alg = String(req.params.alg);
    if (!LEARN_ALGS.has(alg)) {
      res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: "unknown algorithm", stage: "gateway" } });
      return;
    }
    relay(res, await rust.get(learn(`/walkthrough/${alg}`)));
  }),
);
router.post("/learn/experiment", guard(async (req, res) => relay(res, await rust.post(learn("/experiment"), req.body ?? {}))));
router.get("/learn/experiments", guard(async (req, res) => relay(res, await rust.get(learn(`/experiments${rawQuery(req)}`)))));
router.get(
  "/learn/experiments/:id/export",
  guard(async (req, res) => {
    const id = String(req.params.id);
    const fmt = String(req.query.format ?? "json");
    if (!/^[0-9a-f]{32}$/.test(id) || !["json", "csv", "md"].includes(fmt)) {
      res.status(400).json({ ok: false, error: { code: "INVALID_REQUEST", message: "invalid id or format", stage: "gateway" } });
      return;
    }
    const r = await rust.getRaw(learn(`/experiments/${id}/export?format=${fmt}`));
    relayRaw(res, r, r.status === 200 ? { "Content-Disposition": `attachment; filename="learn-${id.slice(0, 12)}.${fmt}"` } : undefined);
  }),
);
