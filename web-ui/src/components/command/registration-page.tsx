import { useCallback, useState } from "react";
import { Fingerprint, ImagePlus, Play, Plus } from "lucide-react";
import { api, type StegoRegistrationResult, type StegoSelection } from "@/lib/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { BusyLabel, DataTable, Empty, ErrorNotice, Field, Flow, PageHeader, Panel, Status, selectClass } from "./core";

// Reads a browser `File` as base64 (no `data:...;base64,` prefix) --
// the same encoding the live `/stego/select-and-embed` HTTP API (and
// this project's Rust<->Python `StegoClient`) already expects, so a
// cover image picked here needs no further transformation before it
// crosses the gateway.
function fileToBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const result = reader.result as string;
      const comma = result.indexOf(",");
      resolve(comma >= 0 ? result.slice(comma + 1) : result);
    };
    reader.onerror = () => reject(reader.error ?? new Error("file read failed"));
    reader.readAsDataURL(file);
  });
}

function CandidateTable({ selection }: { selection: StegoSelection }) {
  return (
    <DataTable label="Steganography algorithm candidates">
      <thead>
        <tr><th>Algorithm</th><th>Feasible</th><th>Score</th><th>Capacity</th><th>Embed ms</th><th>Extract ms</th><th>SSIM</th><th>PSNR dB</th></tr>
      </thead>
      <tbody>
        {selection.candidates.map((c) => (
          <tr key={c.algorithm_id}>
            <td>
              <strong>{c.algorithm_id}</strong>
              {c.algorithm_id === selection.winner_algorithm_id && <Status tone="success">SELECTED</Status>}
            </td>
            <td>{c.feasible ? <Status tone="success">YES</Status> : <Status tone="danger">{c.measurement.reason.toUpperCase()}</Status>}</td>
            <td>{c.feasible ? c.score.toFixed(4) : "—"}</td>
            <td>{c.measurement.capacity_bytes}B</td>
            <td>{c.measurement.embed_time_ms.toFixed(2)}</td>
            <td>{c.measurement.extract_time_ms.toFixed(2)}</td>
            <td>{c.measurement.ssim.toFixed(4)}</td>
            <td>{c.measurement.psnr_db.toFixed(2)}</td>
          </tr>
        ))}
      </tbody>
    </DataTable>
  );
}

export function RegistrationPage() {
  const dronesFetcher = useCallback(() => api.getDrones(), []);
  const groupsFetcher = useCallback(() => api.getGroups(), []);
  const { data: dronesData, refresh: refreshDrones } = usePolling(dronesFetcher, 4000);
  const { data: groupsData } = usePolling(groupsFetcher, 4000);

  const [newDroneId, setNewDroneId] = useState("");
  const [droneId, setDroneId] = useState("");
  const [groupId, setGroupId] = useState("");
  const [role, setRole] = useState("recon");
  const [coverR1, setCoverR1] = useState<{ name: string; b64: string } | null>(null);
  const [coverR3, setCoverR3] = useState<{ name: string; b64: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<StegoRegistrationResult | null>(null);

  const unregistered = (dronesData?.drones ?? []).filter((d) => !d.registered);

  async function createDrone() {
    setBusy(true);
    setError(null);
    try {
      const id = newDroneId.trim();
      await api.createDrone(id);
      setDroneId(id);
      setNewDroneId("");
      await refreshDrones();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function onCover(which: "r1" | "r3", file: File | null) {
    const setCover = which === "r1" ? setCoverR1 : setCoverR3;
    if (!file) {
      setCover(null);
      return;
    }
    try {
      const b64 = await fileToBase64(file);
      setCover({ name: file.name, b64 });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function register() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.registerDroneViaStego(droneId, groupId, role.trim() || "member", coverR1?.b64, coverR3?.b64);
      setResult(r);
      await refreshDrones();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="DEVICE ENROLLMENT / R1–R3"
        title="Registration via Steganography"
        description="Real ML-KEM-768 + ML-DSA-44 enrollment keys, KEM-then-AEAD sealed, RAG-assisted algorithm selection against real measurements, embedded into and extracted from real cover images by python-service -- the same pipeline as iod-register-stego-demo, driven live from here."
        actions={<Status tone="info">LIVE PIPELINE</Status>}
      />
      {error && <ErrorNotice message={error} />}

      <div className="split-grid">
        <Panel title="Capture">
          <div className="form-grid">
            <Field label="New drone identifier" hint="Create a device, then select it below">
              <Input value={newDroneId} onChange={(e) => setNewDroneId(e.target.value)} placeholder="drone-4" />
            </Field>
            <Field label="‌">
              <Button disabled={busy || !newDroneId.trim()} onClick={() => void createDrone()}>
                <Plus />
                Create drone
              </Button>
            </Field>
          </div>
          <Field label="Drone to register">
            <select className={selectClass} value={droneId} onChange={(e) => setDroneId(e.target.value)}>
              <option value="">Select an unregistered drone</option>
              {unregistered.map((d) => (
                <option key={d.drone_id} value={d.drone_id}>{d.drone_id}</option>
              ))}
            </select>
          </Field>
          <div className="form-grid">
            <Field label="R1 cover image (D1 → GCS)" hint="Optional -- a bundled research cover image is used if omitted">
              <input type="file" accept="image/png,image/jpeg" onChange={(e) => void onCover("r1", e.target.files?.[0] ?? null)} />
            </Field>
            <Field label="R3 cover image (GCS → D1)" hint="Optional -- a bundled research cover image is used if omitted">
              <input type="file" accept="image/png,image/jpeg" onChange={(e) => void onCover("r3", e.target.files?.[0] ?? null)} />
            </Field>
          </div>
        </Panel>

        <Panel title="Payload & Group">
          <div className="form-grid">
            <Field label="Target group">
              <select className={selectClass} value={groupId} onChange={(e) => setGroupId(e.target.value)}>
                <option value="">Select group</option>
                {groupsData?.groups.map((g) => (
                  <option key={g.group_id} value={g.group_id}>{g.group_id}</option>
                ))}
              </select>
            </Field>
            <Field label="Operational role">
              <Input value={role} onChange={(e) => setRole(e.target.value)} />
            </Field>
          </div>
          <p className="page-sub">
            The real registration payload -- fresh ML-KEM-768/ML-DSA-44 public keys, PUF-bound leaf randomness, and
            membership metadata -- is generated on-device and KEM-then-AEAD sealed before any pixel is touched. There
            is no separate "file to hide" here: the sealed EnrollmentRequest/EnrollmentResponse bytes are the payload.
          </p>
          <Button disabled={busy || !droneId || !groupId} onClick={() => void register()}>
            <Play />
            <BusyLabel busy={busy} idle="Register via steganography" busyText="Running R1 → R2 → R3" />
          </Button>
          <Flow
            steps={["R1 build + seal", "RAG selection + embed", "R2 GCS-internal", "R3 build + seal + embed", "D1 verifies witness"]}
            active={busy ? 1 : result ? 4 : -1}
          />
        </Panel>
      </div>

      {result && (
        <>
          <Panel title="RAG-Assisted Selection -- R1 (EnrollmentRequest)" meta={<Status tone="success">CHOSE {result.r1_algorithm_id.toUpperCase()}</Status>}>
            <CandidateTable selection={result.r1_selection} />
            <div className="output-block">
              <span>SELECTION NARRATIVE</span>
              <pre>{result.r1_explanation.narrative}</pre>
            </div>
          </Panel>

          <div className="split-grid">
            <Panel title="Stego Preview -- R1 cover image" meta={<ImagePlus />}>
              <img src={`data:image/png;base64,${result.r1_stego_image_b64}`} alt="R1 stego cover image" style={{ maxWidth: "100%", borderRadius: 8, display: "block" }} />
            </Panel>
            <Panel title="Stego Preview -- R3 cover image" meta={<ImagePlus />}>
              <img src={`data:image/png;base64,${result.r3_stego_image_b64}`} alt="R3 stego cover image" style={{ maxWidth: "100%", borderRadius: 8, display: "block" }} />
            </Panel>
          </div>

          <Panel title="RAG-Assisted Selection -- R3 (EnrollmentResponse)" meta={<Status tone="success">CHOSE {result.r3_algorithm_id.toUpperCase()}</Status>}>
            <CandidateTable selection={result.r3_selection} />
            <div className="output-block">
              <span>SELECTION NARRATIVE</span>
              <pre>{result.r3_explanation.narrative}</pre>
            </div>
          </Panel>

          <Panel title="Registration Status" meta={<Status tone="success">REGISTERED</Status>}>
            <dl className="detail-list">
              <div><dt>DRONE</dt><dd>{droneId}</dd></div>
              <div><dt>GROUP</dt><dd>{groupId}</dd></div>
              <div><dt>LEAF INDEX</dt><dd>{result.leaf_index}</dd></div>
              <div><dt>TRANSPORT</dt><dd>Steganographic (R1 + R3)</dd></div>
            </dl>
          </Panel>
        </>
      )}

      {!result && unregistered.length === 0 && (dronesData?.drones.length ?? 0) > 0 && (
        <Empty title="No unregistered drones" description="Every known drone is already registered. Create a new one above to run this flow again." />
      )}

      <p className="page-sub">
        <Fingerprint style={{ width: 12, height: 12, display: "inline", verticalAlign: "-2px", marginRight: 4 }} />
        The original collaborative drone-contribution RAG pipeline (word-overlap retrieval, mock-LLM fusion) still
        exists and still passes its own tests -- it is simply no longer part of the registration path. See
        docs/rag.md for that subsystem.
      </p>
    </>
  );
}
