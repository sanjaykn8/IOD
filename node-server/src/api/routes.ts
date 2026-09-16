import { Router, Request, Response } from "express";
import { rust } from "../services/rustClient";
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
router.post("/trace/request", async (req, res) => relay(res, await rust.post("/api/trace/request", req.body)));
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
