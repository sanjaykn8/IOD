// Shared UI primitives (docs/ui-design-system.md section 5).
import type { ReactNode } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  CircleDot,
  Info,
  LoaderCircle,
  ShieldAlert,
} from "lucide-react";
import { cn } from "@/lib/utils";

export type Tone = "success" | "warning" | "danger" | "info" | "neutral";

export function Status({ children, tone = "neutral" }: { children: ReactNode; tone?: Tone }) {
  const Icon =
    tone === "success"
      ? CheckCircle2
      : tone === "warning"
        ? AlertTriangle
        : tone === "danger"
          ? ShieldAlert
          : tone === "info"
            ? LoaderCircle
            : CircleDot;
  return (
    <span className={cn("status", `status-${tone}`)}>
      <Icon aria-hidden="true" />
      {children}
    </span>
  );
}

/** Page title, one-sentence description, optional actions. `eyebrow` is accepted for compatibility and not rendered. */
export function PageHeader({
  title,
  description,
  actions,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div className="min-w-0">
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

export function Panel({
  title,
  meta,
  description,
  children,
  className,
}: {
  title: string;
  meta?: ReactNode;
  description?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("command-panel", className)} aria-label={title}>
      <header className="panel-header">
        <h2>{title}</h2>
        {meta}
      </header>
      {description && <p className="panel-desc">{description}</p>}
      {children}
    </section>
  );
}

export function Metric({
  label,
  value,
  detail,
  tone = "neutral",
}: {
  label: string;
  value: ReactNode;
  detail?: string;
  tone?: Tone;
}) {
  return (
    <article className={cn("metric", `metric-${tone}`)}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {detail && <div className="metric-detail">{detail}</div>}
    </article>
  );
}

export function KeyValues({
  items,
  className,
}: {
  items: [string, ReactNode, boolean?][];
  className?: string;
}) {
  return (
    <dl className={cn("kv", className)}>
      {items.map(([k, v, mono]) => (
        <div key={k}>
          <dt>{k}</dt>
          <dd className={mono ? "mono" : undefined}>{v ?? "—"}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Collapsed-by-default disclosure for advanced or technical details. */
export function Disclosure({
  summary,
  children,
  open,
  testId,
}: {
  summary: string;
  children: ReactNode;
  open?: boolean;
  testId?: string;
}) {
  return (
    <details className="disclosure" open={open} data-testid={testId}>
      <summary>{summary}</summary>
      <div className="disclosure-body">{children}</div>
    </details>
  );
}

export function Notice({
  tone = "info",
  title,
  children,
}: {
  tone?: "info" | "warning" | "danger";
  title: string;
  children?: ReactNode;
}) {
  const Icon = tone === "danger" ? ShieldAlert : tone === "warning" ? AlertTriangle : Info;
  return (
    <div className={cn("notice", `notice-${tone}`)} role={tone === "danger" ? "alert" : undefined}>
      <Icon aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        {children && <p>{children}</p>}
      </div>
    </div>
  );
}

export function ErrorNotice({ message }: { message: string }) {
  return (
    <Notice tone="danger" title="Request failed">
      {message}
    </Notice>
  );
}

export function Empty({ title, description }: { title: string; description: string }) {
  return (
    <div className="empty-state">
      <CircleDot aria-hidden="true" />
      <strong>{title}</strong>
      <p>{description}</p>
    </div>
  );
}

export function TechnicalId({
  children,
  wrap,
}: {
  children: string | null | undefined;
  wrap?: boolean;
}) {
  const value = children || "—";
  return (
    <span className={cn("technical-id", wrap && "wrap")} title={value}>
      {value}
    </span>
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}

export const selectClass = "control-select";

export function DataTable({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="table-shell" role="region" aria-label={label} tabIndex={0}>
      <table>{children}</table>
    </div>
  );
}

export function Flow({ steps, active = -1 }: { steps: string[]; active?: number }) {
  return (
    <ol className="flow" aria-label="Process stages">
      {steps.map((step, i) => (
        <li key={step} className={i <= active ? "flow-active" : ""}>
          <span>{i + 1}</span>
          <strong>{step}</strong>
        </li>
      ))}
    </ol>
  );
}

export function BusyLabel({
  busy,
  idle,
  busyText,
}: {
  busy: boolean;
  idle: string;
  busyText: string;
}) {
  return (
    <>
      {busy && <LoaderCircle className="animate-spin" aria-hidden="true" />}
      {busy ? busyText : idle}
    </>
  );
}

export function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
