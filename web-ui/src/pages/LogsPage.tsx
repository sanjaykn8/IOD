import { useEffect, useState } from "react";
import { api, streamEvents } from "../services/api";
import type { ProtocolEvent } from "../types/api";

export function LogsPage() {
  const [events, setEvents] = useState<ProtocolEvent[]>([]);
  const [live, setLive] = useState(true);

  useEffect(() => {
    api.getEventsHistory(300).then((r) => setEvents(r.events));
  }, []);

  useEffect(() => {
    if (!live) return;
    const stop = streamEvents((ev) => {
      setEvents((prev) => [...prev, ev].slice(-500));
    });
    return stop;
  }, [live]);

  return (
    <div>
      <h2 className="page-title">Protocol Event Timeline</h2>
      <p className="page-sub">
        Every message across R1–R3, M1–M8, and K1–K4 appears here in real time (via Server-Sent Events from the
        Node gateway). Never shows private keys, PUF secrets, shared secrets, or AEAD keys.
      </p>

      <div className="row" style={{ marginBottom: 12 }}>
        <button className={live ? "" : "secondary"} onClick={() => setLive((v) => !v)}>
          {live ? "Live: ON" : "Live: OFF"}
        </button>
        <button className="secondary" onClick={() => api.getEventsHistory(300).then((r) => setEvents(r.events))}>
          Reload History
        </button>
      </div>

      <div className="panel" style={{ maxHeight: "70vh", overflowY: "auto" }}>
        {events.slice().reverse().map((ev, i) => (
          <div className="event-line" key={i}>
            <span className="ts">{new Date(ev.timestamp_unix_ms).toLocaleTimeString()}</span>
            <span className="stage">{ev.stage}</span>
            <span className={`pill ${ev.status === "Ok" ? "ok" : ev.status === "Fail" ? "fail" : "info"}`}>{ev.status}</span>
            <span>{ev.sender} → {ev.receiver}</span>
            <span style={{ color: "var(--text-dim)" }}>{ev.detail}</span>
          </div>
        ))}
        {events.length === 0 && <p style={{ color: "var(--text-dim)" }}>No events yet — try creating a drone or running authentication.</p>}
      </div>
    </div>
  );
}
