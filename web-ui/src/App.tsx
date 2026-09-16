import { useState } from "react";
import { DashboardPage } from "./pages/DashboardPage";
import { DronesPage } from "./pages/DronesPage";
import { GroupsPage } from "./pages/GroupsPage";
import { AuthenticationPage } from "./pages/AuthenticationPage";
import { SecureCommPage } from "./pages/SecureCommPage";
import { RagPage } from "./pages/RagPage";
import { TracePage } from "./pages/TracePage";
import { LogsPage } from "./pages/LogsPage";
import { SettingsPage } from "./pages/SettingsPage";

const PAGES = [
  { id: "dashboard", label: "Dashboard" },
  { id: "drones", label: "Drones" },
  { id: "groups", label: "Groups" },
  { id: "auth", label: "Authentication" },
  { id: "secure-comm", label: "Secure Communication" },
  { id: "rag", label: "RAG Simulation" },
  { id: "trace", label: "Trace Manager" },
  { id: "logs", label: "Protocol Logs" },
  { id: "settings", label: "Settings" },
] as const;

type PageId = (typeof PAGES)[number]["id"];

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");

  return (
    <div className="app-shell">
      <div className="sidebar">
        <div className="brand">
          <h1>IoD SECURE SIM</h1>
          <p>Post-quantum drone auth research demo</p>
        </div>
        {PAGES.map((p) => (
          <div
            key={p.id}
            className={`nav-item ${page === p.id ? "active" : ""}`}
            onClick={() => setPage(p.id)}
          >
            {p.label}
          </div>
        ))}
      </div>
      <div className="main">
        {page === "dashboard" && <DashboardPage />}
        {page === "drones" && <DronesPage />}
        {page === "groups" && <GroupsPage />}
        {page === "auth" && <AuthenticationPage />}
        {page === "secure-comm" && <SecureCommPage />}
        {page === "rag" && <RagPage />}
        {page === "trace" && <TracePage />}
        {page === "logs" && <LogsPage />}
        {page === "settings" && <SettingsPage />}
      </div>
    </div>
  );
}
