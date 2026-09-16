# Runs the full scripted demonstration procedure against a running
# instance (see run_demo.ps1), printing each step's response.
#
# NOTE: Invoke-RestMethod throws a terminating exception on any 4xx/5xx
# HTTP response (unlike curl, which just returns the body). Several
# steps below (e.g. "attempt authentication again" after revocation)
# are EXPECTED to return an error response -- an earlier draft of this
# script did not account for that and would have crashed at exactly
# that step, before reaching the audit-log/Trace-Manager steps. The
# try/catch below extracts and prints the error body instead of
# aborting the whole script, matching the Linux demo_scenario.sh's
# behavior (curl prints the body and continues either way).
$Base = if ($env:IOD_NODE_BASE) { $env:IOD_NODE_BASE } else { "http://127.0.0.1:4000/api" }

function Invoke-DemoStep($title) { Write-Host ""; Write-Host "### $title" }

function Invoke-DemoCall($method, $path, $body) {
    Write-Host "-> $method $path"
    try {
        if ($body) {
            $resp = Invoke-RestMethod -Method $method -Uri "$Base$path" -Body $body -ContentType "application/json"
        } else {
            $resp = Invoke-RestMethod -Method $method -Uri "$Base$path"
        }
        $resp | ConvertTo-Json -Compress
    } catch {
        # Extract the JSON error body if available (this is the expected,
        # successful path for the "denied" steps below), otherwise show
        # a short message rather than a full stack trace.
        if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
            Write-Host $_.ErrorDetails.Message
        } else {
            Write-Host "(request failed: $($_.Exception.Message))"
        }
    }
}

Invoke-DemoStep "a. GCS is already running (started by run_demo.ps1)"
Invoke-DemoCall GET "/state" $null

Invoke-DemoStep "b/c. Create D1 and D2"
Invoke-DemoCall POST "/drones" '{"drone_id":"drone-1"}'
Invoke-DemoCall POST "/drones" '{"drone_id":"drone-2"}'

Invoke-DemoStep "d. Create group"
Invoke-DemoCall POST "/groups" '{"group_id":"alpha"}'

Invoke-DemoStep "e/f/g. Register D1 and D2 into the group"
Invoke-DemoCall POST "/drones/drone-1/register" '{"group_id":"alpha","role":"recon"}'
Invoke-DemoCall POST "/drones/drone-2/register" '{"group_id":"alpha","role":"recon"}'

Invoke-DemoStep "h. Authenticate D1 -> D2 (expect ALLOW)"
Invoke-DemoCall POST "/authenticate" '{"d1_id":"drone-1","d2_id":"drone-2"}'

Invoke-DemoStep "i. Establish group key"
Invoke-DemoCall POST "/group-key" '{"d1_id":"drone-1","d2_id":"drone-2","mission_id":"demo-mission"}'

Invoke-DemoStep "j. Send a secure message"
Invoke-DemoCall POST "/secure-message" '{"from_id":"drone-1","to_id":"drone-2","plaintext":"Perimeter clear, proceeding to waypoint 2."}'

Invoke-DemoStep "k. Run the RAG simulation"
Invoke-DemoCall POST "/rag/contribute" '{"drone_id":"drone-1","content":"Enemy convoy spotted moving north on route 7, six vehicles","confidence":0.9}'
Invoke-DemoCall POST "/rag/contribute" '{"drone_id":"drone-2","content":"Convoy of 6 vehicles confirmed heading north on route 7","confidence":0.85}'
Invoke-DemoCall POST "/rag/run" '{"query":"What is happening on route 7?"}'

Invoke-DemoStep "l. Revoke D1"
Invoke-DemoCall POST "/drones/drone-1/revoke" $null

Invoke-DemoStep "m/n. Attempt authentication again (expect denial/error)"
Invoke-DemoCall POST "/authenticate" '{"d1_id":"drone-1","d2_id":"drone-2"}'

Invoke-DemoStep "o. Inspect the audit log"
Invoke-DemoCall GET "/events/history?limit=15" $null

Invoke-DemoStep "p. Invoke the Trace Manager (as administrator)"
Invoke-DemoCall POST "/trace/flag" '{"session_id":"demo-session","flagged_by":"operator","reason":"demonstration flag"}'
Invoke-DemoCall GET "/trace" $null

Write-Host ""
Write-Host "Demo scenario complete. See the React dashboard for the visual walkthrough of the same flow."
