import { useCallback, useState } from "react";
import { Link } from "@tanstack/react-router";
import {
  ArrowRight,
  CheckCircle2,
  KeyRound,
  Play,
  Send,
  ShieldCheck,
  ShieldX,
  XCircle,
} from "lucide-react";
import { api, type AuthResultView, type ProtocolEvent } from "@/lib/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import {
  BusyLabel,
  Disclosure,
  ErrorNotice,
  Field,
  Flow,
  PageHeader,
  Panel,
  Status,
  TechnicalId,
  errorText,
  selectClass,
} from "./core";

type Check = { name: string; ok: boolean; how: string };
function checks(r: AuthResultView): Check[] {
  const out: Check[] = [
    { name: "Freshness", ok: r.freshness_ok, how: "timestamps and single-use nonces" },
    { name: "Signatures", ok: r.signature_ok, how: "ML-DSA-44 over the canonical transcript" },
    {
      name: "Group membership",
      ok: r.zk_membership_ok,
      how: "zk-STARK proof against the current Merkle root",
    },
    { name: "Device response", ok: r.puf_ok, how: "challenge-response from the simulated PUF" },
    {
      name: "Root and version",
      ok: r.root_version_ok,
      how: "matches the ground control station state",
    },
  ];
  if (r.credential_ok !== undefined)
    out.push({
      name: "Credential",
      ok: r.credential_ok,
      how: "GCS-signed credential, suite-bound",
    });
  if (r.commitment_ok !== undefined)
    out.push({
      name: "Commitment",
      ok: r.commitment_ok,
      how: "opening matches the committed values",
    });
  if (r.session_binding_ok !== undefined)
    out.push({
      name: "Session binding",
      ok: r.session_binding_ok,
      how: "all messages bound to one session context",
    });
  return out;
}
const STAGES = ["M1", "M2", "M3", "M4", "M5", "M6", "M7", "M8"];

export function AuthenticationPage() {
  const fetcher = useCallback(() => api.getDrones(), []);
  const { data, error: pollError } = usePolling(fetcher, 3000);
  const [initiator, setInitiator] = useState("");
  const [verifier, setVerifier] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<AuthResultView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [events, setEvents] = useState<ProtocolEvent[]>([]);
  async function run() {
    setBusy(true);
    setError(null);
    setResult(null);
    setEvents([]);
    try {
      const r = await api.authenticate(initiator, verifier);
      setResult(r);
      const hist = await api.getEventsHistory(80);
      setEvents(hist.events.filter((e) => e.session_id === r.session_id));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const options = data?.drones.map((d) => <option key={d.drone_id}>{d.drone_id}</option>);
  const allowed = result?.decision === "ALLOW";
  return (
    <>
      <PageHeader
        title="Authentication"
        description="Run the GCS-assisted mutual authentication (M1–M8) between two registered drones and inspect each check."
      />
      {(error || pollError) && <ErrorNotice message={error || pollError || "Unknown error"} />}
      <Panel title="Participants" meta={busy ? <Status tone="info">Running</Status> : undefined}>
        <div className="form-row">
          <Field label="Initiator">
            <select
              aria-label="Initiator"
              className={selectClass}
              value={initiator}
              onChange={(e) => setInitiator(e.target.value)}
            >
              <option value="">Select drone</option>
              {options}
            </select>
          </Field>
          <ArrowRight className="role-arrow" aria-hidden="true" />
          <Field label="Verifier">
            <select
              aria-label="Verifier"
              className={selectClass}
              value={verifier}
              onChange={(e) => setVerifier(e.target.value)}
            >
              <option value="">Select drone</option>
              {options}
            </select>
          </Field>
          <Button
            disabled={busy || !initiator || !verifier || initiator === verifier}
            onClick={() => void run()}
          >
            <Play />
            <BusyLabel busy={busy} idle="Run M1–M8" busyText="Running" />
          </Button>
        </div>
      </Panel>
      {result && (
        <div
          className={allowed ? "decision decision-allow" : "decision decision-deny"}
          role="status"
        >
          {allowed ? <ShieldCheck aria-hidden="true" /> : <ShieldX aria-hidden="true" />}
          <div>
            <strong>{allowed ? "Authenticated" : "Denied"}</strong>
            <p>Reason code {result.reason_code}</p>
          </div>
          <Status tone={allowed ? "success" : "danger"}>
            {allowed ? "Session trusted" : "Access denied"}
          </Status>
        </div>
      )}
      <Panel
        title="Message sequence"
        meta={result ? <TechnicalId>{result.session_id}</TechnicalId> : undefined}
      >
        <ol className="timeline" aria-label="M1 to M8">
          {STAGES.map((m) => {
            // a stage can log several events: a failure wins, then a passed check, then information
            const same = events.filter((e) => e.stage === m);
            const ev =
              same.find((e) => e.status === "Fail") ??
              same.find((e) => e.status === "Ok") ??
              same[0];
            const cls = ev
              ? ev.status === "Ok"
                ? "tl-ok"
                : ev.status === "Fail"
                  ? "tl-fail"
                  : "tl-info"
              : "";
            return (
              <li key={m} className={cls}>
                <strong>{m}</strong>
                <span>{ev ? `${ev.sender} → ${ev.receiver}` : busy ? "Pending" : "Not run"}</span>
              </li>
            );
          })}
        </ol>
        {events.length > 0 && (
          <Disclosure summary={`Event details (${events.length})`}>
            <div className="event-details">
              {events.map((ev) => (
                <div key={`${ev.session_id}-${ev.stage}-${ev.timestamp_unix_ms}-${ev.sender}`}>
                  <Status
                    tone={ev.status === "Ok" ? "success" : ev.status === "Fail" ? "danger" : "info"}
                  >
                    {ev.stage}
                  </Status>
                  <span>
                    {ev.sender} → {ev.receiver}
                  </span>
                  <p>{ev.detail}</p>
                </div>
              ))}
            </div>
          </Disclosure>
        )}
      </Panel>
      {result && (
        <Panel title="Checks">
          <ul className="check-list">
            {checks(result).map((c) => (
              <li key={c.name} className={c.ok ? "ok" : "fail"}>
                {c.ok ? <CheckCircle2 aria-label="passed" /> : <XCircle aria-label="failed" />}
                <div>
                  <strong>{c.name}</strong>
                  <span>{c.how}</span>
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </>
  );
}

export function SecureCommunicationPage() {
  const fetcher = useCallback(() => api.getDrones(), []);
  const { data, error: pollError } = usePolling(fetcher, 3000);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [mission, setMission] = useState("mission-alpha");
  const [message, setMessage] = useState("Perimeter clear, proceeding to waypoint 2.");
  const [keyReady, setKeyReady] = useState(false);
  const [sendResult, setSendResult] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function establish() {
    setBusy(true);
    setError(null);
    setKeyReady(false);
    try {
      await api.establishGroupKey(from, to, mission);
      setKeyReady(true);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  async function send() {
    setBusy(true);
    setError(null);
    setSendResult(null);
    try {
      const r = await api.sendSecureMessage(from, to, message);
      setSendResult(r.decrypted_by_receiver);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const options = data?.drones.map((d) => <option key={d.drone_id}>{d.drone_id}</option>);
  const pair = !!from && !!to && from !== to;
  return (
    <>
      <PageHeader
        title="Secure communication"
        description="Establish a session key (K1–K3) after authentication, then send an encrypted message (K4) and confirm the receiver decrypted it."
      />
      {(error || pollError) && <ErrorNotice message={error || pollError || "Unknown error"} />}
      <Panel
        title="Session key"
        meta={
          <Status tone={keyReady ? "success" : "neutral"}>
            {keyReady ? "Established" : "Not established"}
          </Status>
        }
      >
        <div className="form-row">
          <Field label="From">
            <select
              aria-label="From"
              className={selectClass}
              value={from}
              onChange={(e) => {
                setFrom(e.target.value);
                setKeyReady(false);
              }}
            >
              <option value="">Select drone</option>
              {options}
            </select>
          </Field>
          <ArrowRight className="role-arrow" aria-hidden="true" />
          <Field label="To">
            <select
              aria-label="To"
              className={selectClass}
              value={to}
              onChange={(e) => {
                setTo(e.target.value);
                setKeyReady(false);
              }}
            >
              <option value="">Select drone</option>
              {options}
            </select>
          </Field>
          <Field label="Mission id">
            <Input
              value={mission}
              onChange={(e) => {
                setMission(e.target.value);
                setKeyReady(false);
              }}
            />
          </Field>
          <Button disabled={busy || !pair || !mission} onClick={() => void establish()}>
            <KeyRound />
            <BusyLabel busy={busy} idle="Establish key" busyText="Running K1–K3" />
          </Button>
        </div>
        <Flow
          steps={[
            "Authenticated session",
            "Key request",
            "ML-KEM encapsulation",
            "Key delivery",
            "Key derivation",
            "Confirmation",
            "AEAD channel",
          ]}
          active={keyReady ? 6 : busy ? 2 : -1}
        />
      </Panel>
      <Panel
        title="Message"
        meta={
          <Status tone={sendResult ? "success" : "neutral"}>
            {sendResult ? "Delivered" : "Not sent"}
          </Status>
        }
      >
        <Field label="Plaintext">
          <Textarea
            aria-label="Plaintext"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
            rows={3}
          />
        </Field>
        <div className="button-row" style={{ marginTop: 12 }}>
          <Button disabled={busy || !pair || !message} onClick={() => void send()}>
            <Send />
            <BusyLabel busy={busy} idle="Encrypt and send" busyText="Sending" />
          </Button>
          <span className="stego-muted">
            Messages travel as images through the patch-wise transport.{" "}
            <Link className="inline-link" to="/steganography">
              Inspect in the steganography lab
            </Link>
          </span>
        </div>
        {sendResult && (
          <div className="transport-flow" aria-label="Transport stages">
            <div>
              <span>Sent by {from}</span>
              <p>{message}</p>
            </div>
            <div>
              <span>Sealed</span>
              <p>ChaCha20-Poly1305 under the session key</p>
            </div>
            <div>
              <span>Carried</span>
              <p>PNG image, keyed bootstrap-v3 carrier</p>
            </div>
            <div>
              <span>Decrypted by {to}</span>
              <p>{sendResult}</p>
            </div>
          </div>
        )}
      </Panel>
    </>
  );
}
