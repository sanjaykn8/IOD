import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2, CircleDot, LoaderCircle, ShieldAlert } from "lucide-react";
import { cn } from "@/lib/utils";
export type Tone="success"|"warning"|"danger"|"info"|"neutral";
export function Status({children,tone="neutral"}:{children:ReactNode;tone?:Tone}){const Icon=tone==="success"?CheckCircle2:tone==="warning"?AlertTriangle:tone==="danger"?ShieldAlert:tone==="info"?LoaderCircle:CircleDot;return <span className={cn("status",`status-${tone}`)}><Icon aria-hidden="true"/>{children}</span>}
export function PageHeader({eyebrow,title,description,actions}:{eyebrow:string;title:string;description:string;actions?:ReactNode}){return <header className="page-header"><div className="min-w-0"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{description}</p></div>{actions&&<div className="page-actions">{actions}</div>}</header>}
export function Panel({title,meta,children,className}:{title:string;meta?:ReactNode;children:ReactNode;className?:string}){return <section className={cn("command-panel",className)}><header className="panel-header"><h2>{title}</h2>{meta}</header>{children}</section>}
export function Metric({label,value,detail,tone="neutral"}:{label:string;value:ReactNode;detail:string;tone?:Tone}){return <article className={cn("metric",`metric-${tone}`)}><div className="metric-label">{label}</div><div className="metric-value">{value}</div><div className="metric-detail"><span className="telemetry-dot"/>{detail}</div></article>}
export function ErrorNotice({message}:{message:string}){return <div className="notice notice-danger" role="alert"><ShieldAlert aria-hidden="true"/><div><strong>Connection or operation failed</strong><p>{message}</p></div></div>}
export function Empty({title,description}:{title:string;description:string}){return <div className="empty-state"><CircleDot aria-hidden="true"/><strong>{title}</strong><p>{description}</p></div>}
export function TechnicalId({children}:{children:string|null|undefined}){const value=children||"—";return <span className="technical-id" title={value}>{value}</span>}
export function Field({label,children,hint}:{label:string;children:ReactNode;hint?:string}){return <label className="field"><span>{label}</span>{children}{hint&&<small>{hint}</small>}</label>}
export const selectClass="control-select";
export function DataTable({children,label}:{children:ReactNode;label:string}){return <div className="table-shell" role="region" aria-label={label} tabIndex={0}><table>{children}</table></div>}
export function Flow({steps,active=-1}:{steps:string[];active?:number}){return <ol className="flow" aria-label="Process stages">{steps.map((step,i)=><li key={step} className={i<=active?"flow-active":""}><span>{String(i+1).padStart(2,"0")}</span><strong>{step}</strong></li>)}</ol>}
export function BusyLabel({busy,idle,busyText}:{busy:boolean;idle:string;busyText:string}){return <>{busy&&<LoaderCircle className="animate-spin" aria-hidden="true"/>}{busy?busyText:idle}</>}
