export function Pill({ ok, label }: { ok: boolean; label?: string }) {
  return <span className={`pill ${ok ? "ok" : "fail"}`}>{label ?? (ok ? "OK" : "FAIL")}</span>;
}
