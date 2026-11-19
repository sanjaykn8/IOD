import { useCallback, useState } from "react";
import { Network, Plus, RefreshCw, ShieldCheck } from "lucide-react";
import { api, type DroneView } from "@/lib/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  BusyLabel,
  DataTable,
  Disclosure,
  Empty,
  ErrorNotice,
  Field,
  KeyValues,
  Metric,
  PageHeader,
  Panel,
  Status,
  TechnicalId,
  errorText,
  selectClass,
} from "./core";

function droneStatus(d: DroneView) {
  if (!d.registered) return <Status tone="warning">Unregistered</Status>;
  if (d.active) return <Status tone="success">Active</Status>;
  return <Status tone="danger">Revoked</Status>;
}

/** Short, human label for the suite id the backend reports (the full id is in the tooltip). */
function SuiteLabel({ suite }: { suite: string | null }) {
  if (!suite) return <span className="text-muted-foreground">—</span>;
  const known = suite === "iod-fips203-mlkem768-fips204-mldsa44-v1";
  return <span title={suite}>{known ? "ML-KEM-768 + ML-DSA-44" : suite}</span>;
}

export function OverviewPage() {
  const fetcher = useCallback(() => api.getState(), []);
  const { data, error, refresh } = usePolling(fetcher, 3000);
  const active = data?.drones.filter((d) => d.active).length ?? 0;
  return (
    <>
      <PageHeader
        title="Overview"
        description="Current simulation state from the ground control station. Refreshes every three seconds."
        actions={
          <Button variant="outline" size="sm" onClick={() => void refresh()}>
            <RefreshCw />
            Refresh
          </Button>
        }
      />
      {error && <ErrorNotice message={error} />}
      <div className="metrics-grid">
        <Metric
          label="Ground control station"
          value={error ? "Unreachable" : data ? "Responding" : "—"}
          tone={error ? "danger" : "neutral"}
        />
        <Metric label="Active drones" value={data ? `${active} of ${data.drone_count}` : "—"} />
        <Metric label="Groups" value={data?.group_count ?? "—"} />
        <Metric label="Protocol events" value={data?.event_count ?? "—"} />
      </div>
      <Panel
        title="Fleet"
        meta={
          <span className="panel-count">
            {data?.drones.length ?? 0} {data?.drones.length === 1 ? "drone" : "drones"}
          </span>
        }
      >
        <DataTable label="Fleet">
          <thead>
            <tr>
              <th>Drone</th>
              <th>Group</th>
              <th>State</th>
              <th>Role</th>
              <th>Suite</th>
            </tr>
          </thead>
          <tbody>
            {data?.drones.map((d) => (
              <tr key={d.drone_id}>
                <td>
                  <strong>{d.drone_id}</strong>
                </td>
                <td>{d.group_id ?? "—"}</td>
                <td>{droneStatus(d)}</td>
                <td>{d.role ?? "—"}</td>
                <td>
                  <SuiteLabel suite={d.crypto_suite} />
                </td>
              </tr>
            ))}
            {data && data.drones.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <Empty
                    title="No drones yet"
                    description="Create and register drones on the Drones page."
                  />
                </td>
              </tr>
            )}
          </tbody>
        </DataTable>
      </Panel>
      <Panel
        title="Groups"
        meta={
          <span className="panel-count">
            {data?.groups.length ?? 0} {data?.groups.length === 1 ? "group" : "groups"}
          </span>
        }
      >
        <DataTable label="Groups">
          <thead>
            <tr>
              <th>Group</th>
              <th className="num">Version</th>
              <th className="num">Members</th>
              <th className="num">Capacity</th>
              <th>Merkle root</th>
            </tr>
          </thead>
          <tbody>
            {data?.groups.map((g) => (
              <tr key={g.group_id}>
                <td>
                  <strong>{g.group_id}</strong>
                </td>
                <td className="num">{g.version}</td>
                <td className="num">{g.active_members.length}</td>
                <td className="num">{g.capacity}</td>
                <td>
                  <TechnicalId>{g.root_hex}</TechnicalId>
                </td>
              </tr>
            ))}
            {data && data.groups.length === 0 && (
              <tr>
                <td colSpan={5}>
                  <Empty title="No groups yet" description="Create a group on the Groups page." />
                </td>
              </tr>
            )}
          </tbody>
        </DataTable>
      </Panel>
    </>
  );
}

export function DronesPage() {
  const fetcher = useCallback(() => api.getDrones(), []);
  const groupsFetcher = useCallback(() => api.getGroups(), []);
  const { data, error, loading, refresh } = usePolling(fetcher, 3000);
  const { data: groupsData } = usePolling(groupsFetcher, 3000);
  const [newId, setNewId] = useState("");
  const [regDrone, setRegDrone] = useState("");
  const [regGroup, setRegGroup] = useState("");
  const [regRole, setRegRole] = useState("member");
  const [moveDrone, setMoveDrone] = useState("");
  const [moveGroup, setMoveGroup] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  async function run(fn: () => Promise<unknown>) {
    setBusy(true);
    setActionError(null);
    try {
      await fn();
      await refresh();
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  const droneOptions = data?.drones.map((d) => <option key={d.drone_id}>{d.drone_id}</option>);
  const groupOptions = groupsData?.groups.map((g) => (
    <option key={g.group_id}>{g.group_id}</option>
  ));
  return (
    <>
      <PageHeader
        title="Drones"
        description="Create drones, register them in a group, and revoke or reactivate membership. Only public-key fingerprints are shown."
      />
      {(error || actionError) && <ErrorNotice message={actionError || error || "Unknown error"} />}
      <div className="operation-grid section-gap">
        <Panel title="Create drone">
          <Field label="Drone id">
            <Input value={newId} onChange={(e) => setNewId(e.target.value)} placeholder="drone-3" />
          </Field>
          <Button
            disabled={busy || !newId.trim()}
            onClick={() => void run(() => api.createDrone(newId.trim())).then(() => setNewId(""))}
          >
            <Plus />
            <BusyLabel busy={busy} idle="Create drone" busyText="Working" />
          </Button>
        </Panel>
        <Panel title="Register in a group">
          <div className="form-grid">
            <Field label="Drone">
              <select
                className={selectClass}
                value={regDrone}
                onChange={(e) => setRegDrone(e.target.value)}
              >
                <option value="">Select</option>
                {droneOptions}
              </select>
            </Field>
            <Field label="Group">
              <select
                className={selectClass}
                value={regGroup}
                onChange={(e) => setRegGroup(e.target.value)}
              >
                <option value="">Select</option>
                {groupOptions}
              </select>
            </Field>
          </div>
          <Field label="Role">
            <Input value={regRole} onChange={(e) => setRegRole(e.target.value)} />
          </Field>
          <Button
            disabled={busy || !regDrone || !regGroup}
            onClick={() => void run(() => api.registerDrone(regDrone, regGroup, regRole))}
          >
            <ShieldCheck />
            Register
          </Button>
        </Panel>
        <Panel title="Move to another group">
          <div className="form-grid">
            <Field label="Drone">
              <select
                className={selectClass}
                value={moveDrone}
                onChange={(e) => setMoveDrone(e.target.value)}
              >
                <option value="">Select</option>
                {droneOptions}
              </select>
            </Field>
            <Field label="Group">
              <select
                className={selectClass}
                value={moveGroup}
                onChange={(e) => setMoveGroup(e.target.value)}
              >
                <option value="">Select</option>
                {groupOptions}
              </select>
            </Field>
          </div>
          <Button
            disabled={busy || !moveDrone || !moveGroup}
            onClick={() => void run(() => api.moveDrone(moveDrone, moveGroup))}
          >
            <Network />
            Move
          </Button>
        </Panel>
      </div>
      <Panel
        title="Fleet"
        meta={
          <span className="panel-count">
            {data?.drones.length ?? 0} {data?.drones.length === 1 ? "drone" : "drones"}
          </span>
        }
      >
        <DataTable label="Drone inventory">
          <thead>
            <tr>
              <th>Drone</th>
              <th>Group</th>
              <th>State</th>
              <th className="num">Leaf</th>
              <th>Suite</th>
              <th>ML-KEM-768 key</th>
              <th>ML-DSA-44 key</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {data?.drones.map((d) => (
              <tr key={d.drone_id}>
                <td>
                  <strong>{d.drone_id}</strong>
                  <small>{d.role ?? "No role"}</small>
                </td>
                <td>{d.group_id ?? "—"}</td>
                <td>{droneStatus(d)}</td>
                <td className="num">{d.leaf_index ?? "—"}</td>
                <td>
                  <SuiteLabel suite={d.crypto_suite} />
                </td>
                <td>
                  <TechnicalId>{d.kem_pk_fingerprint}</TechnicalId>
                </td>
                <td>
                  <TechnicalId>{d.sig_pk_fingerprint}</TechnicalId>
                </td>
                <td>
                  <div className="table-actions">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy || !d.active}
                      onClick={() => void run(() => api.revokeDrone(d.drone_id))}
                    >
                      Revoke
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={busy || d.active || !d.registered}
                      onClick={() => void run(() => api.reactivateDrone(d.drone_id))}
                    >
                      Reactivate
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
            {!loading && data?.drones.length === 0 && (
              <tr>
                <td colSpan={8}>
                  <Empty title="No drones yet" description="Create the first drone above." />
                </td>
              </tr>
            )}
          </tbody>
        </DataTable>
        <Disclosure summary="Cached group state per drone">
          <DataTable label="Cached group state">
            <thead>
              <tr>
                <th>Drone</th>
                <th className="num">Cached version</th>
                <th>Cached Merkle root</th>
              </tr>
            </thead>
            <tbody>
              {data?.drones.map((d) => (
                <tr key={d.drone_id}>
                  <td>{d.drone_id}</td>
                  <td className="num">{d.cached_version ?? "—"}</td>
                  <td>
                    <TechnicalId>{d.cached_root_hex}</TechnicalId>
                  </td>
                </tr>
              ))}
            </tbody>
          </DataTable>
          <p className="stego-muted">
            Fingerprints are 8-byte SHAKE-256 digests of the public keys, bound to the suite id.
            Private keys stay in the core.
          </p>
        </Disclosure>
      </Panel>
    </>
  );
}

export function GroupsPage() {
  const fetcher = useCallback(() => api.getGroups(), []);
  const { data, error, refresh } = usePolling(fetcher, 3000);
  const [id, setId] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  async function create() {
    setBusy(true);
    setActionError(null);
    try {
      await api.createGroup(id.trim());
      setId("");
      await refresh();
    } catch (e) {
      setActionError(errorText(e));
    } finally {
      setBusy(false);
    }
  }
  return (
    <>
      <PageHeader
        title="Groups"
        description="Each group is a Merkle membership tree (Poseidon2) kept by the ground control station; drones hold only their own witness."
      />
      {(error || actionError) && <ErrorNotice message={actionError || error || "Unknown error"} />}
      <Panel title="Create group">
        <div className="inline-form">
          <Field label="Group id">
            <Input value={id} onChange={(e) => setId(e.target.value)} placeholder="bravo" />
          </Field>
          <Button disabled={busy || !id.trim()} onClick={() => void create()}>
            <Plus />
            <BusyLabel busy={busy} idle="Create group" busyText="Creating" />
          </Button>
        </div>
      </Panel>
      <div className="group-grid">
        {data?.groups.map((g) => (
          <article className="group-card" key={g.group_id}>
            <header>
              <h2>{g.group_id}</h2>
              <Status tone={g.active_members.length ? "success" : "neutral"}>
                {g.active_members.length ? "In use" : "Empty"}
              </Status>
            </header>
            <KeyValues
              items={[
                ["Version", g.version],
                ["Members", g.active_members.length],
                ["Capacity", g.capacity],
              ]}
            />
            <KeyValues items={[["Active members", g.active_members.join(", ") || "None"]]} />
            <Disclosure summary="Merkle root">
              <TechnicalId wrap>{g.root_hex}</TechnicalId>
            </Disclosure>
          </article>
        ))}
        {data && data.groups.length === 0 && (
          <div className="span-full">
            <Empty
              title="No groups yet"
              description="Create a group to start registering drones."
            />
          </div>
        )}
      </div>
    </>
  );
}
