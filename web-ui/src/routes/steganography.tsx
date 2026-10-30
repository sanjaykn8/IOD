import { createFileRoute } from "@tanstack/react-router";
import { SteganographyLabTabs } from "@/components/command/stego-tabs";

export const Route = createFileRoute("/steganography")({
  head: () => ({
    meta: [
      { title: "Steganography Lab — Cypher Command Center" },
      { name: "description", content: "Image-transported application messages (live UAV flow) and an educational workbench with worked calculations for ten steganography algorithms." },
      { property: "og:title", content: "Steganography Lab — Cypher Command Center" },
      { property: "og:description", content: "Send K4 application messages as PNG images and inspect every stage." },
      { property: "og:type", content: "website" },
    ],
  }),
  component: SteganographyLabTabs,
});
