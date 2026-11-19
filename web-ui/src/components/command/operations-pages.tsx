import { useCallback, useEffect, useMemo, useState } from "react";
import { Flag, Radio, RefreshCw, Search, Trash2 } from "lucide-react";
import { api, streamEvents, type ProtocolEvent, type SystemCrypto } from "@/lib/api";
import { stegoApi } from "@/lib/stego-api";
import type { StegoStatus } from "@/types/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
  BusyLabel,
  DataTable,
  Disclosure,
  Empty,
  ErrorNotice,
  Field,
  KeyValues,
  Notice,
  PageHeader,
  Panel,
  Status,
  TechnicalId,
  errorText,
  selectClass,
} from "./core";

export function TracePage() {
  const fetcher = useCallback(() => api.getTrace(), []);
  const { data, error: pollError, refresh } = usePolling(fetcher, 4000);
  const [session, setSession] = useState("");
  const [flagReason, setFlagReason] = useState("");
  const [pid, setPid] = useState("");
  const [token, setToken] = useState("");
  const [requester, setRequester] = useState("admin-1");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  async function act(fn: () => Promise<unknown>, clear: () => void) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      clear();
      await refresh();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title="Trace manager"
        description="Flag suspicious sessions and request pseudonym resolution. Every request, granted or denied, is written to the audit trail."
      />
      <Notice tone="warning" title="Administrator token required">
        The core checks the token (IOD_ADMIN_TOKEN). A trace also needs a reason and a PID from a
        flagged session.
      </Notice>
      {(error || pollError) && <ErrorNotice message={error || pollError || "Unknown error"} />}
      <div className="split-grid section-gap">
        <Panel title="Flag a session">
          <Field label="Session id">
            <Input
              value={session}
              onChange={(e) => setSession(e.target.value)}
              placeholder="Authentication session id"
            />
          </Field>
          <Field label="Reason">
            <Input value={flagReason} onChange={(e) => setFlagReason(e.target.value)} />
          </Field>
          <Button
            variant="outline"
            disabled={busy || !session || !flagReason}
            onClick={() =>
              void act(
                () => api.flagSession(session, "operator", flagReason),
                () => {
                  setSession("");
                  setFlagReason("");
                },
              )
            }
          >
            <Flag />
            Flag session
          </Button>
        </Panel>
        <Panel title="Request a trace">
          <div className="form-grid">
            <Field label="Requested by">
              <Input value={requester} onChange={(e) => setRequester(e.target.value)} />
            </Field>
            <Field label="Administrator token">
              <Input
                type="password"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="IOD_ADMIN_TOKEN"
              />
            </Field>
          </div>
          <Field label="Pseudonym (PID, hex)">
            <Input value={pid} onChange={(e) => setPid(e.target.value)} />
          </Field>
          <Field label="Reason">
            <Input value={reason} onChange={(e) => setReason(e.target.value)} />
          </Field>
          <Button
            variant="destructive"
            disabled={busy || !pid || !reason}
            onClick={() =>
              void act(
                () => api.requestTrace(requester, reason, pid, token),
                () => {
                  setPid("");
                  setReason("");
                },
              )
            }
          >
            <Search />
            <BusyLabel busy={busy} idle="Request trace" busyText="Checking" />
          </Button>
        </Panel>
      </div>
      <Panel title="Flags" meta={<span className="panel-count">{data?.flags.length ?? 0}</span>}>
        <DataTable label="Suspicion flags">
          <thead>
            <tr>
              <th>Time</th>
              <th>Session</th>
              <th>Flagged by</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {data?.flags.map((f) => (
              <tr key={f.flag_id}>
                <td>{new Date(f.timestamp_unix_ms).toLocaleString()}</td>
                <td>
                  <TechnicalId>{f.session_id}</TechnicalId>
                </td>
                <td>{f.flagged_by}</td>
                <td>{f.reason}</td>
              </tr>
            ))}
            {data && data.flags.length === 0 && (
              <tr>
                <td colSpan={4}>
                  <Empty title="No flags" description="No session is under review." />
                </td>
              </tr>
            )}
          </tbody>
        </DataTable>
      </Panel>
      <Panel
        title="Audit trail"
        meta={<span className="panel-count">{data?.trace_records.length ?? 0}</span>}
      >
        <DataTable label="Trace audit trail">
          <thead>
            <tr>
              <th>Time</th>
              <th>Requested by</th>
              <th>Role</th>
              <th>Decision</th>
              <th>Resolved drone</th>
              <th>Reason</th>
            </tr>
          </thead>
          <tbody>
            {data?.trace_records.map((t) => (
              <tr key={t.trace_id}>
                <td>{new Date(t.timestamp_unix_ms).toLocaleString()}</td>
                <td>{t.requested_by}</td>
                <td>{t.requester_role}</td>
                <td>
                  <Status tone={t.authorized ? "success" : "danger"}>
                    {t.authorized ? "Granted" : "Denied"}
                  </Status>
                </td>
                <td>{t.authorized ? t.resolved_drone_id || "Unresolved" : "Withheld"}</td>
                <td>{t.reason}</td>
              </tr>
            ))}
            {data && data.trace_records.length === 0 && (
              <tr>
                <td colSpan={6}>
                  <Empty
                    title="No trace requests"
                    description="Requests appear here as soon as they are made."
                  />
                </td>
              </tr>
            )}
          </tbody>
        </DataTable>
      </Panel>
    </>
  );
}

export function LogsPage() {
  const [events, setEvents] = useState<ProtocolEvent[]>([]);
  const [live, setLive] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState("ALL");
  const [stage, setStage] = useState("");
  const [text, setText] = useState("");
  async function reload() {
    try {
      const r = await api.getEventsHistory(300);
      setEvents(r.events);
      setError(null);
    } catch (e) {
      setError(errorText(e));
    }
  }
  useEffect(() => {
    void reload();
  }, []);
  useEffect(() => {
    if (!live) {
      setConnected(false);
      return;
    }
    return streamEvents((ev) => setEvents((prev) => [...prev, ev].slice(-500)), setConnected);
  }, [live]);
  const filtered = useMemo(
    () =>
      events
        .filter(
          (e) =>
            (status === "ALL" || e.status === status) &&
            (!stage || e.stage.toLowerCase().includes(stage.toLowerCase())) &&
            (!text ||
              `${e.sender} ${e.receiver} ${e.session_id} ${e.detail}`
                .toLowerCase()
                .includes(text.toLowerCase())),
        )
        .reverse(),
    [events, status, stage, text],
  );
  return (
    <>
      <PageHeader
        title="Event log"
        description="Protocol events for registration (R1–R3), authentication (M1–M8) and key establishment (K1–K4), with live updates."
        actions={
          <Status tone={!live ? "neutral" : connected ? "success" : "warning"}>
            {!live ? "Live updates off" : connected ? "Live" : "Reconnecting"}
          </Status>
        }
      />
      {error && <ErrorNotice message={error} />}
      <Panel title="Filters">
        <div className="filter-grid">
          <Field label="Status">
            <select
              className={selectClass}
              value={status}
              onChange={(e) => setStatus(e.target.value)}
            >
              <option value="ALL">All</option>
              <option value="Ok">Passed</option>
              <option value="Info">Information</option>
              <option value="Fail">Failed</option>
            </select>
          </Field>
          <Field label="Stage">
            <Input
              value={stage}
              onChange={(e) => setStage(e.target.value)}
              placeholder="M5, K2, R1"
            />
          </Field>
          <Field label="Drone, session or text">
            <Input value={text} onChange={(e) => setText(e.target.value)} />
          </Field>
          <div className="button-row">
            <Button variant={live ? "default" : "outline"} onClick={() => setLive((v) => !v)}>
              <Radio />
              {live ? "Live on" : "Live off"}
            </Button>
            <Button variant="outline" onClick={() => void reload()}>
              <RefreshCw />
              Reload
            </Button>
          </div>
        </div>
      </Panel>
      <Panel
        title="Events"
        meta={
          <span className="panel-count">
            {filtered.length} of {events.length}
          </span>
        }
      >
        <div className="log-console">
          {filtered.map((ev) => (
            <article key={`${ev.session_id}-${ev.stage}-${ev.timestamp_unix_ms}-${ev.sender}`}>
              <time>
                {new Date(ev.timestamp_unix_ms).toLocaleTimeString([], { hour12: false })}
              </time>
              <span className="log-stage">{ev.stage}</span>
              <span className="log-route">
                {ev.sender} → {ev.receiver}
              </span>
              <p>{ev.detail}</p>
              <Status
                tone={ev.status === "Ok" ? "success" : ev.status === "Fail" ? "danger" : "info"}
              >
                {ev.status === "Ok" ? "Passed" : ev.status === "Fail" ? "Failed" : "Info"}
              </Status>
            </article>
          ))}
          {filtered.length === 0 && (
            <Empty
              title="No matching events"
              description="Change the filters or run a protocol step."
            />
          )}
        </div>
      </Panel>
    </>
  );
}

function fmtBytes(n: number | undefined) {
  return n === undefined ? "—" : `${n.toLocaleString()} B`;
}

export function SystemPage() {
  const cryptoFetcher = useCallback(() => api.getSystemCrypto(), []);
  const { data: crypto, error: cryptoError } = usePolling<SystemCrypto>(cryptoFetcher, 15000);
  const [stego, setStego] = useState<StegoStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    void stegoApi.status().then((r) => {
      if (r.ok) setStego(r.data);
    });
  }, []);
  async function reset() {
    setBusy(true);
    setError(null);
    try {
      await api.reset();
      setStatus("Simulation reset. Drones, groups, sessions and events were cleared.");
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const s = crypto?.suite;
  const kem = s?.sizes.ml_kem_768;
  const sig = s?.sizes.ml_dsa_44;
  const policy = stego?.config?.algorithm_policy;
  const boot = stego?.config?.bootstrap;
  const archived = crypto?.migration.legacy_snapshots?.count ?? 0;
  return (
    <>
      <PageHeader
        title="System"
        description="Active cryptographic suite, transport configuration and simulation controls, as reported by the core."
      />
      {(error || cryptoError) && <ErrorNotice message={error || cryptoError || "Unknown error"} />}
      <Panel
        title="Cryptographic suite"
        meta={s ? <Status tone="success">Active</Status> : undefined}
      >
        <KeyValues
          items={[
            ["Suite id", s?.suite_id, true],
            ["Key encapsulation", s ? `${s.kem}` : undefined],
            ["Signatures", s ? `${s.signature}` : undefined],
            ["AEAD", s?.aead],
            ["Key derivation", s?.kdf],
            ["Transcript hash", s?.transcript_hash],
          ]}
        />
        <div className="grid-2" style={{ marginTop: 16 }}>
          <DataTable label="ML-KEM-768 sizes">
            <thead>
              <tr>
                <th>ML-KEM-768</th>
                <th className="num">Bytes</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Public key</td>
                <td className="num">{fmtBytes(kem?.public_key)}</td>
              </tr>
              <tr>
                <td>Private key (expanded)</td>
                <td className="num">{fmtBytes(kem?.private_key_expanded)}</td>
              </tr>
              <tr>
                <td>Private key (stored seed)</td>
                <td className="num">{fmtBytes(kem?.private_key_seed)}</td>
              </tr>
              <tr>
                <td>Ciphertext</td>
                <td className="num">{fmtBytes(kem?.ciphertext)}</td>
              </tr>
              <tr>
                <td>Shared secret</td>
                <td className="num">{fmtBytes(kem?.shared_secret)}</td>
              </tr>
            </tbody>
          </DataTable>
          <DataTable label="ML-DSA-44 sizes">
            <thead>
              <tr>
                <th>ML-DSA-44</th>
                <th className="num">Bytes</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Public key</td>
                <td className="num">{fmtBytes(sig?.public_key)}</td>
              </tr>
              <tr>
                <td>Private key (expanded)</td>
                <td className="num">{fmtBytes(sig?.private_key_expanded)}</td>
              </tr>
              <tr>
                <td>Private key (stored seed)</td>
                <td className="num">{fmtBytes(sig?.private_key_seed)}</td>
              </tr>
              <tr>
                <td>Signature</td>
                <td className="num">{fmtBytes(sig?.signature)}</td>
              </tr>
            </tbody>
          </DataTable>
        </div>
        <Notice
          tone="info"
          title={s?.validation ? `Conformance tested; ${s.validation}` : "Conformance"}
        >
          {s?.conformance}
        </Notice>
        <Disclosure summary="Implementation details">
          <KeyValues
            items={[
              ["ML-KEM implementation", s?.kem_implementation],
              ["ML-DSA implementation", s?.signature_implementation],
              ["Signing mode", s?.signature_mode],
              ["Private key storage", s?.private_key_storage],
              ["Key generation", s?.key_generation],
              ["Retired suite", s?.legacy_suite, true],
            ]}
          />
        </Disclosure>
      </Panel>
      <div className="split-grid section-gap">
        <Panel title="Device identity">
          <KeyValues
            items={[
              [
                "PUF",
                <Status key="p" tone="warning">
                  Simulated
                </Status>,
              ],
              ["Model", crypto?.puf],
            ]}
          />
          <KeyValues
            className="mt-4"
            items={[
              [
                "Stored identities from other suites",
                archived ? `${archived} archived (not loaded)` : "None",
              ],
            ]}
          />
          {archived > 0 && <p className="stego-muted">{crypto?.migration.action}</p>}
        </Panel>
        <Panel title="Image transport">
          <KeyValues
            items={[
              ["Format", stego?.transport?.format_version, true],
              ["Algorithm policy", policy?.name],
              ["Allowed", policy?.allowed?.join(", ")],
              ["Bootstrap", boot ? `v${boot.version}, sync window ${boot.sync_window}` : undefined],
            ]}
          />
          {policy?.excluded && policy.excluded.length > 0 && (
            <Disclosure summary={`Excluded algorithms (${policy.excluded.length})`}>
              <DataTable label="Excluded algorithms">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {policy.excluded.map((x) => (
                    <tr key={x.algorithm}>
                      <td className="mono">{x.algorithm}</td>
                      <td>{x.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </DataTable>
            </Disclosure>
          )}
          {!stego && (
            <p className="stego-muted">
              Transport status unavailable (image service or gateway not reachable).
            </p>
          )}
        </Panel>
      </div>
      <Panel title="Services">
        <DataTable label="Service endpoints">
          <thead>
            <tr>
              <th>Service</th>
              <th>Default address</th>
              <th>Role</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>Node gateway</td>
              <td>
                <TechnicalId>http://127.0.0.1:4000</TechnicalId>
              </td>
              <td>Browser boundary, relays to the core</td>
            </tr>
            <tr>
              <td>Rust core</td>
              <td>
                <TechnicalId>http://127.0.0.1:8787</TechnicalId>
              </td>
              <td>Protocol, cryptography, transport authority</td>
            </tr>
            <tr>
              <td>Python image service</td>
              <td>
                <TechnicalId>http://127.0.0.1:5001</TechnicalId>
              </td>
              <td>Cover generation and pixel work; holds no keys</td>
            </tr>
          </tbody>
        </DataTable>
        <p className="stego-muted">
          Loopback only, no TLS between services. Research prototype; Raspberry Pi measurements and
          the radio/UAV link are deferred.
        </p>
      </Panel>
      <Panel title="Reset simulation" className="danger-zone">
        <p>Clears every drone, group, session and protocol event. This cannot be undone.</p>
        <AlertDialog>
          <AlertDialogTrigger asChild>
            <Button variant="destructive">
              <Trash2 />
              Reset simulation
            </Button>
          </AlertDialogTrigger>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Reset the simulation?</AlertDialogTitle>
              <AlertDialogDescription>
                All drones, groups, sessions, keys held by the simulation and protocol events are
                removed.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>Cancel</AlertDialogCancel>
              <AlertDialogAction
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                disabled={busy}
                onClick={() => void reset()}
              >
                {busy ? "Resetting…" : "Reset"}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
        {status && (
          <p className="success-copy" role="status">
            {status}
          </p>
        )}
      </Panel>
    </>
  );
}
