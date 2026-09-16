import { useState } from "react";
import { api } from "../services/api";

export function SettingsPage() {
  const [confirming, setConfirming] = useState(false);
  const [status, setStatus] = useState<string | null>(null);

  async function reset() {
    await api.reset();
    setStatus("Simulation reset: all drones, groups, sessions, and logs cleared.");
    setConfirming(false);
  }

  return (
    <div>
      <h2 className="page-title">Settings / System Information</h2>
      <p className="page-sub">Endpoints, cryptographic configuration, and simulation reset.</p>

      <div className="panel">
        <h3>Service Endpoints</h3>
        <table>
          <tbody>
            <tr><td>Node.js API gateway</td><td className="mono">http://127.0.0.1:4000</td></tr>
            <tr><td>Rust core HTTP API</td><td className="mono">http://127.0.0.1:8787</td></tr>
            <tr><td>Python RAG service</td><td className="mono">http://127.0.0.1:5001</td></tr>
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Cryptographic Configuration</h3>
        <table>
          <tbody>
            <tr><td>KEM</td><td>Kyber768 (NIST Round-3; ML-KEM-768/FIPS 203 predecessor)</td></tr>
            <tr><td>Signature</td><td>Dilithium2 (NIST Round-3; ML-DSA-44/FIPS 204 predecessor)</td></tr>
            <tr><td>Hash (in-circuit)</td><td>Poseidon over a 64-bit Goldilocks-style prime field (no elliptic curve)</td></tr>
            <tr><td>Hash (transcripts)</td><td>SHAKE256 / HMAC-SHA256 / HKDF-SHA256</td></tr>
            <tr><td>AEAD</td><td>ChaCha20-Poly1305</td></tr>
            <tr><td>ZK membership proof</td><td>Transparent, hash-based research simulation (see docs/zk-membership.md — witness disclosed to the verifier; not a hiding ZK proof)</td></tr>
            <tr><td>ECC used anywhere</td><td><span className="pill ok">NONE</span></td></tr>
          </tbody>
        </table>
      </div>

      <div className="panel">
        <h3>Reset Simulation</h3>
        <p style={{ fontSize: 13, color: "var(--text-dim)" }}>
          Deletes every drone, group, session, and log entry from the local database. This cannot be undone.
        </p>
        {!confirming && <button className="danger" onClick={() => setConfirming(true)}>Reset Simulation…</button>}
        {confirming && (
          <div className="row">
            <span>Are you sure?</span>
            <button className="danger" onClick={reset}>Yes, reset everything</button>
            <button className="secondary" onClick={() => setConfirming(false)}>Cancel</button>
          </div>
        )}
        {status && <p style={{ color: "var(--ok)", marginTop: 10 }}>{status}</p>}
      </div>
    </div>
  );
}
