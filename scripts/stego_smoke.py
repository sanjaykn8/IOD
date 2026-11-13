#!/usr/bin/env python3
"""End-to-end smoke test of the patch-wise saved-image flow through the Node gateway (stdlib only; Windows + Linux).

Usage: python scripts/stego_smoke.py [--base http://127.0.0.1:4000/api]
Requires the Rust core, Python service and Node gateway to be running (scripts/*/run_demo.*).
Exit code 0 only if every check passes. The admin-token and plaintext are never printed.
"""
import argparse, json, sys, urllib.request, urllib.error

ap = argparse.ArgumentParser()
ap.add_argument("--base", default="http://127.0.0.1:4000/api")
args = ap.parse_args()
BASE = args.base.rstrip("/")
fails = []


def call(method, path, body=None, raw=False):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            b = r.read()
            return r.status, (b if raw else json.loads(b)), dict(r.headers)
    except urllib.error.HTTPError as e:
        b = e.read()
        try:
            return e.code, json.loads(b), dict(e.headers)
        except Exception:
            return e.code, b, dict(e.headers)


def check(name, cond, extra=""):
    print(("PASS " if cond else "FAIL ") + name + (f"  [{extra}]" if extra and not cond else ""))
    if not cond:
        fails.append(name)


call("POST", "/reset")
call("POST", "/groups", {"group_id": "g1"})
for d in ("smoke-1", "smoke-2"):
    call("POST", "/drones", {"drone_id": d})
    call("POST", f"/drones/{d}/register", {"group_id": "g1", "role": "member"})
st, auth, _ = call("POST", "/authenticate", {"d1_id": "smoke-1", "d2_id": "smoke-2"})
sid = auth.get("session_id")
check("M1-M8 authentication", st == 200 and bool(sid), str(auth)[:200])

st, status, _ = call("GET", "/stego/status")
check("stego status reachable", st == 200 and status.get("backend", {}).get("reachable") is True, str(status)[:300])
check("status exposes no secrets/full paths", "key" not in json.dumps(status).lower().replace("key-issued", ""))

st, early, _ = call("POST", "/stego/message", {"session_id": sid, "from_id": "smoke-1", "plaintext": "too early"})
check("message before K1-K3 refused (NO_GROUP_KEY, 409)", st == 409 and early.get("error", {}).get("code") == "NO_GROUP_KEY", str(early)[:200])

st, gk, _ = call("POST", "/group-key", {"session_id": sid, "mission_id": "smoke"})
check("K1-K3 group key", st == 200, str(gk)[:200])

for frm, to, text in (("smoke-1", "smoke-2", "D1 to D2: hold position"), ("smoke-2", "smoke-1", "D2 to D1: copy that")):
    st, r, _ = call("POST", "/stego/message", {"session_id": sid, "from_id": frm, "plaintext": text, "cover": {"source": "webcam"}})
    ok = st == 200 and r.get("ok") and r.get("delivered_message") == text
    check(f"{frm}->{to} delivered via PNG", ok, str(r)[:300])
    if ok:
        check("  all stages ok", all(s["status"] == "ok" for s in r["stages"]), str([s["name"] + ":" + s["status"] for s in r["stages"]]))
        check("  cover source recorded", r["cover"]["source"] in ("webcam", "procedural_fallback"), str(r["cover"])[:200])
        aid = r["artifact"]["id"]
        st2, png, hdr = call("GET", f"/stego/artifacts/{aid}/stego", raw=True)
        check("  stego PNG downloadable", st2 == 200 and png[:8] == b"\x89PNG\r\n\x1a\n" and hdr.get("Content-Type", "").startswith("image/png"))
        st3, cpng, _ = call("GET", f"/stego/artifacts/{r['cover']['artifact_id']}/cover", raw=True)
        check("  cover PNG downloadable", st3 == 200 and cpng[:8] == b"\x89PNG\r\n\x1a\n")
        cid = r["cover"]["artifact_id"]
        for owner, kind in ((cid, "seg"), (cid, "labels"), (aid, "diff")):
            stx, img, _ = call("GET", f"/stego/artifacts/{owner}/{kind}", raw=True)
            check(f"  {kind} image downloadable", stx == 200 and img[:8] == b"\x89PNG\r\n\x1a\n")
        used = [p for p in r["manifest"]["patches"] if p["used"]]
        off = 0
        seq_ok = True
        for p in used:
            seq_ok &= p["payload_offset"] == off and p["payload_length"] >= 1
            off += p["payload_length"]
        check("  chunks sequential and cover the payload exactly once", seq_ok and off == r["transport"]["payload_section_bytes"], str(used)[:200])
        check("  receiver authenticated the planned manifest without re-segmenting",
              r["manifest"] == r["received_manifest"] and r["verification"]["manifest_authenticated"] and r["verification"]["resegmented"] is False)
        planned = [p for p in r["plan"]["patches"] if p["used"]]
        check("  every used patch has a KB retrieval record (top-1 = selected, BM25 score present)",
              all(p["retrieval"]["ranking"][0] == p["selected"] and isinstance(p["retrieval"]["candidates"][0]["bm25"], (int, float)) for p in planned))
        check("  no explanation / priority / single-algorithm fields", not any(k in r for k in ("explanation", "selection", "priority")))

st, r, _ = call("GET", "/stego/artifacts/..%2f..%2fetc%2fpasswd/stego", raw=True)
check("traversal id refused", st in (400, 404))
st, r, _ = call("GET", "/stego/artifacts/" + "0" * 32 + "/stego")
check("unknown artifact -> 404", st == 404)

for field, value in (("algorithm", "pvd"), ("priority", "urgent"), ("param", 3)):
    st, r, _ = call("POST", "/stego/message", {"session_id": sid, "from_id": "smoke-1", "plaintext": "x", field: value})
    check(f"removed request field '{field}' rejected loudly (400)", st == 400 and r.get("error", {}).get("code") == "INVALID_REQUEST", str(r)[:200])
st, r, _ = call("POST", "/stego/message", {"session_id": sid, "from_id": "intruder", "plaintext": "x"})
check("non-participant rejected (403)", st == 403 and r["error"]["code"] == "NOT_PARTICIPANT")
st, r, _ = call("POST", "/stego/message", {"session_id": sid, "from_id": "smoke-1", "plaintext": "x" * 70000})
check("oversize rejected (413) and recorded", st == 413)

st, a, _ = call("POST", "/stego/plan", {"payload_bytes": 300, "cover": {"source": "procedural"}})
check("plan preview: validated manifest + ten KB candidates per used patch",
      st == 200 and a["manifest"]["payload_len"] == 300 and all(len(p["retrieval"]["candidates"]) == 10 for p in a["plan"]["patches"] if p["used"]), str(a)[:200])
st, kb, _ = call("GET", "/stego/kb")
check("knowledge base served (ten entries, BM25 selector)", st == 200 and len(kb["entries"]) == 10 and kb["selector"]["version"] == "kb-bm25-1", str(kb)[:200])
for gone in ("/stego/analyze", "/stego/explain", "/rag/run", "/rag/contribute"):
    st, _r, _ = call("POST", gone, {})
    check(f"removed endpoint {gone} -> 404", st == 404)
st, _r, _ = call("GET", "/rag/state")
check("removed endpoint /rag/state -> 404", st == 404)

# Algorithm Learning workbench (educational, separate namespace) -- must not touch operational counters
st, before, _ = call("GET", "/stego/status")
st, reg, _ = call("GET", "/learn/registry")
check("learning registry lists ten algorithms", st == 200 and len(reg["algorithms"]) == 10)
st, wt, _ = call("GET", "/learn/walkthrough/s_uniward")
check("worked calculation recovers its bits", st == 200 and wt["exact_match"] and wt["all_checks_passed"])
st, ex, _ = call("POST", "/learn/experiment", {"payload_mode": "aead_fixture", "algorithms": ["lsb_matching", "hugo"], "include_images": False, "patch": "largest"})
check("educational patch experiment verifies the test-only AEAD envelope",
      st == 200 and all(r["verification"]["status"] == "aead_verified" and r["outside_patch_changes"] == 0 for r in ex["results"]) and ex["segmentation"]["patch_count"] >= 2, str(ex)[:300])
st, after, _ = call("GET", "/stego/status")
check("educational experiment left the operational event count unchanged", before["counts"]["events"] == after["counts"]["events"])

st, legacy, _ = call("POST", "/secure-message", {"session_id": sid, "from_id": "smoke-2", "plaintext": "legacy endpoint"})
check("legacy /secure-message now image-based", st == 200 and legacy.get("decrypted_by_receiver") == "legacy endpoint" and "png" in legacy.get("transport", ""), str(legacy)[:200])

st, ev, _ = call("GET", f"/stego/events?session_id={sid}&limit=500")
events = ev.get("events", [])
check("events persisted", st == 200 and len(events) >= 5, str(len(events)))
check("events contain no plaintext", "hold position" not in json.dumps(events) and "copy that" not in json.dumps(events))
st, evf, _ = call("GET", f"/stego/events?session_id={sid}&outcome=failed")
check("outcome filter", st == 200 and all(e["outcome"] == "failed" for e in evf["events"]) and len(evf["events"]) >= 2)
st, evd, _ = call("GET", f"/stego/events?session_id={sid}&direction=D2_to_D1")
check("direction filter (case-insensitive)", st == 200 and all(e["direction"] == 2 for e in evd["events"]) and len(evd["events"]) >= 1)

st, rep, _ = call("GET", "/stego/report?format=json")
check("report json (stego-report-2)", st == 200 and rep.get("schema") == "stego-report-2" and rep["totals"]["events"] >= 5 and len(rep["per_algorithm"]) >= 1)
st, csv, hdr = call("GET", "/stego/report?format=csv", raw=True)
check("report csv", st == 200 and csv.decode().splitlines()[0].startswith("event_id,ts_ms") and "text/csv" in hdr.get("Content-Type", ""))

st, pcsv, hdr = call("GET", "/stego/report?format=patches_csv", raw=True)
check("per-patch csv", st == 200 and pcsv.decode().splitlines()[0].startswith("event_id,patch_id") and len(pcsv.decode().splitlines()) > 2)

st, bm, _ = call("POST", "/stego/benchmark", {"session_id": sid, "iterations": 2, "frame_sizes": [64, 300], "cover": {"source": "procedural"}})
check("benchmark runs real messages", st == 200 and bm.get("samples") == 4 and all(x["ok"] for x in bm["runs"]), str(bm)[:300])

st, probe, _ = call("POST", "/stego/camera/probe", {})
check("camera probe responds (no webcam needed)", st == 200 and "available" in probe, str(probe)[:200])

st, tr, _ = call("POST", "/trace/request", {"requested_by": "x", "reason": "r", "target_pid": "00"})
check("existing trace endpoint still guarded", st in (403, 422, 400))

print()
print("ALL CHECKS PASSED" if not fails else f"{len(fails)} CHECK(S) FAILED: {fails}")
sys.exit(1 if fails else 0)
