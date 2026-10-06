export interface DroneView { drone_id:string; group_id:string|null; registered:boolean; active:boolean; revoked_flag:boolean; kem_pk_fingerprint:string|null; dil_pk_fingerprint:string|null; role:string|null; leaf_index:number|null; cached_root_hex:string|null; cached_version:number|null }
export interface GroupView { group_id:string; root_hex:string; version:number; capacity:number; active_members:string[] }
export interface AuthResultView { session_id:string; freshness_ok:boolean; zk_membership_ok:boolean; signature_ok:boolean; puf_ok:boolean; root_version_ok:boolean; decision:"ALLOW"|"DENY"; reason_code:string }
export interface ProtocolEvent { session_id:string; stage:string; sender:string; receiver:string; timestamp_unix_ms:number; status:"Info"|"Ok"|"Fail"; detail:string }
export interface StateOverview { group_count:number; drone_count:number; groups:GroupView[]; drones:DroneView[]; event_count:number }
export interface Contribution { drone_id:string; content:string; confidence:number; timestamp_unix_ms:number; trust_score:number; flagged_suspicious:boolean; flag_reason:string }
export interface RagRunResult { query:string; llm_provider:string; retrieved_count:number; contributions:Contribution[]; fused_context:string; included_drone_ids:string[]; excluded_drone_ids:string[]; generated_output:string }
export interface TraceFlag { flag_id:string; session_id:string; flagged_by:string; reason:string; timestamp_unix_ms:number }
export interface TraceRecord { trace_id:string; requested_by:string; requester_role:string; reason:string; target_pid_hex:string; authorized:boolean; resolved_drone_id:string|null; timestamp_unix_ms:number }
export interface StegoMeasurement { algorithm_id:string; feasible:boolean; reason:string; capacity_bytes:number; payload_bytes:number; embed_time_ms:number; extract_time_ms:number; mse:number; psnr_db:number; ssim:number; output_size_bytes:number }
export interface StegoCandidate { algorithm_id:string; feasible:boolean; score:number; time_score:number; capacity_score:number; distortion_score:number; measurement:StegoMeasurement }
export interface StegoSelection { winner_algorithm_id:string|null; importance:string; weights:{time:number;capacity:number;distortion:number}; candidates:StegoCandidate[]; reason:string }
export interface StegoEvidence { algorithm_id:string; heading:string; text:string; relevance:number }
export interface StegoExplanation { algorithm_id:string; narrative:string; measurement_used:StegoMeasurement; evidence:StegoEvidence[] }
export interface StegoRegistrationResult {
 leaf_index:number;
 r1_algorithm_id:string; r1_profile_id:string; r1_stego_image_b64:string; r1_selection:StegoSelection; r1_explanation:StegoExplanation;
 r3_algorithm_id:string; r3_profile_id:string; r3_stego_image_b64:string; r3_selection:StegoSelection; r3_explanation:StegoExplanation;
}
const BASE=import.meta.env["VITE_API_BASE"]||"http://127.0.0.1:4000/api";
async function req<T>(method:string,path:string,body?:unknown):Promise<T>{const init:RequestInit={method};if(body!==undefined){init.headers={"Content-Type":"application/json"};init.body=JSON.stringify(body)}const res=await fetch(`${BASE}${path}`,init);const json=await res.json().catch(()=>({}));if(!res.ok)throw new Error((json as {error?:string}).error||`Request failed (${res.status})`);return json as T}
export const api={
 reset:()=>req<{status:string}>("POST","/reset"), getState:()=>req<StateOverview>("GET","/state"),
 createGroup:(group_id:string)=>req<{status:string}>("POST","/groups",{group_id}), getGroups:()=>req<{groups:GroupView[]}>("GET","/groups"), getGroup:(id:string)=>req<GroupView>("GET",`/groups/${encodeURIComponent(id)}`),
 createDrone:(drone_id:string)=>req<{status:string}>("POST","/drones",{drone_id}), getDrones:()=>req<{drones:DroneView[]}>("GET","/drones"),
 registerDrone:(id:string,group_id:string,role:string)=>req<{status:string;leaf_index:number}>("POST",`/drones/${encodeURIComponent(id)}/register`,{group_id,role}),
 revokeDrone:(id:string)=>req<{status:string}>("POST",`/drones/${encodeURIComponent(id)}/revoke`), reactivateDrone:(id:string)=>req<{status:string;leaf_index:number}>("POST",`/drones/${encodeURIComponent(id)}/reactivate`), moveDrone:(id:string,group_id:string)=>req<{status:string;leaf_index:number}>("POST",`/drones/${encodeURIComponent(id)}/move`,{group_id}),
 authenticate:(d1_id:string,d2_id:string)=>req<AuthResultView>("POST","/authenticate",{d1_id,d2_id}), establishGroupKey:(d1_id:string,d2_id:string,mission_id:string)=>req<{status:string}>("POST","/group-key",{d1_id,d2_id,mission_id}), sendSecureMessage:(from_id:string,to_id:string,plaintext:string)=>req<{status:string;decrypted_by_receiver:string}>("POST","/secure-message",{from_id,to_id,plaintext}),
 getEventsHistory:(limit=200)=>req<{events:ProtocolEvent[]}>("GET",`/events/history?limit=${limit}`),
 ragContribute:(drone_id:string,content:string,confidence:number)=>req<{status:string;contribution:Contribution}>("POST","/rag/contribute",{drone_id,content,confidence}), ragRun:(query:string,top_k=5)=>req<RagRunResult>("POST","/rag/run",{query,top_k}), ragState:()=>req<{contributions:Contribution[];last_run_result:Partial<RagRunResult>;llm_provider:string}>("GET","/rag/state"), ragReset:()=>req<{status:string}>("POST","/rag/reset"),
 flagSession:(session_id:string,flagged_by:string,reason:string)=>req<TraceFlag>("POST","/trace/flag",{session_id,flagged_by,reason}), requestTrace:(requested_by:string,requester_role:string,reason:string,target_pid_hex:string)=>req<TraceRecord>("POST","/trace/request",{requested_by,requester_role,reason,target_pid_hex}), getTrace:()=>req<{flags:TraceFlag[];trace_records:TraceRecord[]}>("GET","/trace"),
 stegoAlgorithms:()=>req<{algorithms:string[]}>("GET","/stego/algorithms"),
 registerDroneViaStego:(id:string,group_id:string,role:string,cover_image_r1_b64?:string,cover_image_r3_b64?:string)=>req<StegoRegistrationResult>("POST",`/drones/${encodeURIComponent(id)}/register-stego`,{group_id,role,cover_image_r1_b64,cover_image_r3_b64})
};
export function streamEvents(onEvent:(ev:ProtocolEvent)=>void,onState?:(connected:boolean)=>void){const source=new EventSource(`${BASE}/events/stream`);source.onopen=()=>onState?.(true);source.onerror=()=>onState?.(false);source.onmessage=(msg)=>{try{onEvent(JSON.parse(msg.data) as ProtocolEvent)}catch{}};return()=>source.close()}
