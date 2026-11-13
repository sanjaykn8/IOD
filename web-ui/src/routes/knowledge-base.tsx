import { createFileRoute } from "@tanstack/react-router";
import { KnowledgeBasePage } from "@/components/command/kb-monitor";

export const Route = createFileRoute("/knowledge-base")({
  head: () => ({
    meta: [
      { title: "Knowledge Base / Retrieval Monitor — Cypher Command Center" },
      { name: "description", content: "Static algorithm knowledge base and the deterministic per-patch retrieval (structured filters, BM25, top-1) of the patch-wise steganography transport." },
      { property: "og:title", content: "Knowledge Base / Retrieval Monitor — Cypher Command Center" },
      { property: "og:description", content: "Inspect knowledge-base entries, BM25 settings and per-patch retrieval results." },
      { property: "og:type", content: "website" },
    ],
  }),
  component: KnowledgeBasePage,
});
