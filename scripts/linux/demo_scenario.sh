#!/usr/bin/env bash
# Runs the full scripted demonstration procedure against a running
# instance (see run_demo.sh) via curl, printing each step's response.
# Mirrors exactly the walkthrough in the project README.
set -euo pipefail
BASE="${IOD_NODE_BASE:-http://127.0.0.1:4000/api}"

step() { echo ""; echo "### $1"; }
call() { echo "-> $1 $2"; curl -s -X "$1" "$BASE$2" ${3:+-d "$3"} -H "Content-Type: application/json"; echo; }

step "a. GCS is already running (started by run_demo.sh)"
call GET /state

step "b/c. Create D1 and D2"
call POST /drones '{"drone_id":"drone-1"}'
call POST /drones '{"drone_id":"drone-2"}'

step "d. Create group"
call POST /groups '{"group_id":"alpha"}'

step "e/f/g. Register D1 and D2 into the group"
call POST /drones/drone-1/register '{"group_id":"alpha","role":"recon"}'
call POST /drones/drone-2/register '{"group_id":"alpha","role":"recon"}'

step "h. Authenticate D1 -> D2 (expect ALLOW)"
call POST /authenticate '{"d1_id":"drone-1","d2_id":"drone-2"}'

step "i. Establish group key"
call POST /group-key '{"d1_id":"drone-1","d2_id":"drone-2","mission_id":"demo-mission"}'

step "j. Send a secure message"
call POST /secure-message '{"from_id":"drone-1","to_id":"drone-2","plaintext":"Perimeter clear, proceeding to waypoint 2."}'

step "k. Run the RAG simulation"
call POST /rag/contribute '{"drone_id":"drone-1","content":"Enemy convoy spotted moving north on route 7, six vehicles","confidence":0.9}'
call POST /rag/contribute '{"drone_id":"drone-2","content":"Convoy of 6 vehicles confirmed heading north on route 7","confidence":0.85}'
call POST /rag/run '{"query":"What is happening on route 7?"}'

step "l. Revoke D1"
call POST /drones/drone-1/revoke

step "m/n. Attempt authentication again (expect denial/error)"
call POST /authenticate '{"d1_id":"drone-1","d2_id":"drone-2"}'

step "o. Inspect the audit log"
call GET "/events/history?limit=15"

step "p. Invoke the Trace Manager (as administrator)"
call POST /trace/flag '{"session_id":"demo-session","flagged_by":"operator","reason":"demonstration flag"}'
call GET /trace

echo ""
echo "Demo scenario complete. See the React dashboard for the visual walkthrough of the same flow."
