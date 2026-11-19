// Steganography Lab with two clearly separated views:
//   * Transport — the operational patch-wise flow (policy + risk-aware per-patch selection, keyed bootstrap carrier)
//   * Algorithm learning — worked calculations and experiments (educational workbench)
import { useEffect, useState } from "react";
import { GraduationCap, Radio } from "lucide-react";
import { SteganographyLabPage } from "./stego-lab";
import { LearningWorkbench } from "./learn-workbench";
import { PageHeader } from "./core";

type View = "live" | "learn";

function initialView(): View {
  if (typeof window === "undefined") return "live";
  return new URLSearchParams(window.location.search).get("view") === "learn" ? "learn" : "live";
}

export function SteganographyLabTabs() {
  const [view, setView] = useState<View>("live");
  useEffect(() => setView(initialView()), []);
  function select(v: View) {
    setView(v);
    if (typeof window !== "undefined") {
      const u = new URL(window.location.href);
      if (v === "learn") u.searchParams.set("view", "learn");
      else u.searchParams.delete("view");
      window.history.replaceState(null, "", u.toString());
    }
  }
  return (
    <>
      <PageHeader
        title="Steganography lab"
        description={
          view === "live"
            ? "Send a message as a PNG: the core seals it, the image service generates a fresh cover and embeds it patch by patch, and the receiver verifies the saved file."
            : "Worked calculations and same-input comparisons of all ten algorithms. Educational only: nothing here is a UAV transmission."
        }
      />
      <div className="lab-tabs" role="tablist" aria-label="Steganography lab views">
        <button
          type="button"
          role="tab"
          aria-selected={view === "live"}
          className={`lab-tab ${view === "live" ? "lab-tab-on" : ""}`}
          onClick={() => select("live")}
          data-testid="tab-live"
        >
          <Radio aria-hidden="true" />
          <span>
            <strong>Transport</strong>
          </span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={view === "learn"}
          className={`lab-tab ${view === "learn" ? "lab-tab-on" : ""}`}
          onClick={() => select("learn")}
          data-testid="tab-learn"
        >
          <GraduationCap aria-hidden="true" />
          <span>
            <strong>Algorithm learning</strong>
          </span>
        </button>
      </div>
      {view === "live" ? <SteganographyLabPage /> : <LearningWorkbench />}
    </>
  );
}
