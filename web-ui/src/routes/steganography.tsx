import { createFileRoute } from "@tanstack/react-router";
import { SteganographyLabPage } from "@/components/command/stego-lab";

export const Route = createFileRoute("/steganography")({
  head: () => ({
    meta: [
      { title: "Steganography Lab — Cypher Command Center" },
      { name: "description", content: "Image-transported application messages: algorithm selection, embedding metrics, verification timeline and reports." },
      { property: "og:title", content: "Steganography Lab — Cypher Command Center" },
      { property: "og:description", content: "Send K4 application messages as PNG images and inspect every stage." },
      { property: "og:type", content: "website" },
    ],
  }),
  component: SteganographyLabPage,
});
