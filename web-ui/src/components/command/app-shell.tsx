import { Link,Outlet,useRouterState } from "@tanstack/react-router";
import { Activity,ChevronLeft,ChevronRight,Command,Drone,FileClock,Fingerprint,LayoutDashboard,Menu,MessageSquareLock,Moon,Network,Radio,Settings,ShieldCheck,Siren,Sun,Users,X } from "lucide-react";
import { useEffect,useState } from "react";
import { api } from "@/lib/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
// NOTE: the former "/rag" nav entry (RAG / Knowledge -- the collaborative
// drone-contribution chatbot page) has been replaced here by "/registration"
// (Registration via Steganography), the registration-time RAG-assisted
// algorithm-selection flow -- see docs/architecture.md and docs/rag.md's
// "Historical subsystem" section. The old page and its route still exist
// and still work (reachable directly at /rag); it is simply no longer
// load-bearing for registration, so it is no longer in primary navigation.
const nav=[
 {to:"/",label:"Overview",icon:LayoutDashboard},{to:"/drones",label:"Drones",icon:Drone},{to:"/groups",label:"Groups",icon:Users},{to:"/authentication",label:"Authentication",icon:ShieldCheck},{to:"/secure-communication",label:"Secure Communication",icon:MessageSquareLock},{to:"/registration",label:"Registration (Stego)",icon:Fingerprint},{to:"/trace",label:"Trace Manager",icon:Siren},{to:"/logs",label:"Event Log",icon:FileClock},{to:"/system",label:"System",icon:Settings},
] as const;
export function AppShell(){const path=useRouterState({select:s=>s.location.pathname});const [collapsed,setCollapsed]=useState(false);const [mobile,setMobile]=useState(false);const [theme,setTheme]=useState<"dark"|"light">("dark");const fetcher=()=>api.getState();const {data,error}=usePolling(fetcher,3000);const current=nav.find(n=>n.to===path)?.label||"Command Center";useEffect(()=>{const saved=window.localStorage.getItem("cypher-theme");if(saved==="light"||saved==="dark")setTheme(saved)},[]);useEffect(()=>{document.documentElement.classList.toggle("light-theme",theme==="light");return()=>document.documentElement.classList.remove("light-theme")},[theme]);function toggleTheme(){setTheme(currentTheme=>{const next=currentTheme==="dark"?"light":"dark";window.localStorage.setItem("cypher-theme",next);return next})}return <div className={`${collapsed?"app-shell sidebar-collapsed":"app-shell"} ${theme}`}>
 <aside className={mobile?"command-sidebar mobile-open":"command-sidebar"} aria-label="Primary navigation">
  <div className="brand-block"><div className="brand-mark"><ShieldCheck/></div><div className="brand-copy"><strong>CYPHER</strong><span>COMMAND CENTER</span></div><Button variant="ghost" size="icon" className="mobile-close" onClick={()=>setMobile(false)} aria-label="Close navigation"><X/></Button></div>
  <div className="mission-chip"><span>SIMULATION NODE</span><strong>{error?"DISCONNECTED":"GCS / LOCAL"}</strong></div>
  <nav className="side-nav">{nav.map(({to,label,icon:Icon})=><Link key={to} to={to} activeOptions={{exact:to==="/"}} className="nav-link" activeProps={{className:"nav-link-active"}} title={collapsed?label:undefined} onClick={()=>setMobile(false)}><Icon/><span>{label}</span></Link>)}</nav>
  <div className="sidebar-status"><div><span className={error?"status-light danger":"status-light"}/><p>GCS STATUS</p><strong>{error?"OFFLINE":"OPERATIONAL"}</strong></div><div><Radio/><p>EVENT BUS</p><strong>STANDBY</strong></div></div>
  <Button variant="ghost" size="sm" className="collapse-button" onClick={()=>setCollapsed(v=>!v)} aria-label={collapsed?"Expand navigation":"Collapse navigation"}>{collapsed?<ChevronRight/>:<ChevronLeft/>}<span>Collapse</span></Button>
 </aside>
 {mobile&&<button className="sidebar-scrim" onClick={()=>setMobile(false)} aria-label="Close navigation overlay"/>}
 <div className="app-workspace"><header className="command-bar"><div className="command-left"><Button variant="ghost" size="icon" className="mobile-menu" onClick={()=>setMobile(true)} aria-label="Open navigation"><Menu/></Button><div><span>ACTIVE CONSOLE</span><strong>{current}</strong></div></div><div className="command-signals"><div><Activity/><span>EVENTS</span><strong>{data?.event_count??"—"}</strong></div><div><Network/><span>GROUPS</span><strong>{data?.group_count??"—"}</strong></div><div><Drone/><span>DRONES</span><strong>{data?.drone_count??"—"}</strong></div><div className="operator"><Command/><span>RESEARCH MODE</span><strong>LOCAL OPERATOR</strong></div><Button variant="ghost" size="icon" className="theme-toggle" onClick={toggleTheme} aria-label={`Switch to ${theme==="dark"?"light":"dark"} mode`} title={`Switch to ${theme==="dark"?"light":"dark"} mode`}>{theme==="dark"?<Sun/>:<Moon/>}</Button></div></header><main className="main-canvas"><Outlet/></main></div>
 </div>}
