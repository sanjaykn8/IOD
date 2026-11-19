import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import {
  BookOpen,
  ChevronLeft,
  ChevronRight,
  Drone,
  FileClock,
  ImageIcon,
  LayoutDashboard,
  Menu,
  MessageSquareLock,
  Moon,
  Settings,
  ShieldCheck,
  Siren,
  Sun,
  Users,
  X,
} from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { usePolling } from "@/hooks/use-polling";
import { Button } from "@/components/ui/button";
import { Status } from "./core";

type NavItem = { to: string; label: string; icon: typeof LayoutDashboard };
// Grouped navigation (docs/ui-design-system.md section 4)
const navGroups: { group: string | null; items: NavItem[] }[] = [
  { group: null, items: [{ to: "/", label: "Overview", icon: LayoutDashboard }] },
  {
    group: "Fleet",
    items: [
      { to: "/drones", label: "Drones", icon: Drone },
      { to: "/groups", label: "Groups", icon: Users },
    ],
  },
  {
    group: "Protocols",
    items: [
      { to: "/authentication", label: "Authentication", icon: ShieldCheck },
      { to: "/secure-communication", label: "Secure communication", icon: MessageSquareLock },
    ],
  },
  {
    group: "Analysis",
    items: [
      { to: "/steganography", label: "Steganography lab", icon: ImageIcon },
      { to: "/knowledge-base", label: "Knowledge base", icon: BookOpen },
    ],
  },
  {
    group: "Audit",
    items: [
      { to: "/trace", label: "Trace manager", icon: Siren },
      { to: "/logs", label: "Event log", icon: FileClock },
    ],
  },
  { group: null, items: [{ to: "/system", label: "System", icon: Settings }] },
];
const allItems = navGroups.flatMap((g) => g.items);

export function AppShell() {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const fetcher = useCallback(() => api.getState(), []);
  const { data, error } = usePolling(fetcher, 3000);
  const current = allItems.find((n) => n.to === path)?.label ?? "IoD research simulator";

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem("cypher-theme");
      if (saved === "light" || saved === "dark") setTheme(saved);
    } catch {
      /* storage unavailable: keep the default */
    }
  }, []);
  useEffect(() => {
    document.documentElement.classList.toggle("light-theme", theme === "light");
    return () => document.documentElement.classList.remove("light-theme");
  }, [theme]);
  function toggleTheme() {
    setTheme((t) => {
      const next = t === "dark" ? "light" : "dark";
      try {
        window.localStorage.setItem("cypher-theme", next);
      } catch {
        /* ignore */
      }
      return next;
    });
  }

  return (
    <div className={collapsed ? "app-shell sidebar-collapsed" : "app-shell"}>
      <aside
        className={mobile ? "command-sidebar mobile-open" : "command-sidebar"}
        aria-label="Primary navigation"
      >
        <div className="brand-block">
          <div className="brand-mark">
            <ShieldCheck aria-hidden="true" />
          </div>
          <div className="brand-copy">
            <strong>IoD simulator</strong>
            <span>Research prototype</span>
          </div>
          <Button
            variant="ghost"
            size="icon"
            className="mobile-close"
            onClick={() => setMobile(false)}
            aria-label="Close navigation"
          >
            <X />
          </Button>
        </div>
        <nav className="side-nav">
          {navGroups.map((g, gi) => (
            <div key={g.group ?? `g${gi}`} role="group" aria-label={g.group ?? undefined}>
              {g.group && <div className="nav-group">{g.group}</div>}
              {g.items.map(({ to, label, icon: Icon }) => (
                <Link
                  key={to}
                  to={to}
                  activeOptions={{ exact: to === "/" }}
                  className="nav-link"
                  activeProps={{ className: "nav-link-active" }}
                  title={collapsed ? label : undefined}
                  onClick={() => setMobile(false)}
                >
                  <Icon aria-hidden="true" />
                  <span>{label}</span>
                </Link>
              ))}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <p>Local simulation. Not a production deployment.</p>
          <Button
            variant="ghost"
            size="sm"
            className="collapse-button"
            onClick={() => setCollapsed((v) => !v)}
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
          >
            {collapsed ? <ChevronRight /> : <ChevronLeft />}
            <span>Collapse</span>
          </Button>
        </div>
      </aside>
      {mobile && (
        <button
          className="sidebar-scrim"
          onClick={() => setMobile(false)}
          aria-label="Close navigation overlay"
        />
      )}
      <div className="app-workspace">
        <header className="command-bar">
          <div className="command-left">
            <Button
              variant="ghost"
              size="icon"
              className="mobile-menu"
              onClick={() => setMobile(true)}
              aria-label="Open navigation"
            >
              <Menu />
            </Button>
            <strong>{current}</strong>
          </div>
          <div className="command-signals">
            {error ? (
              <Status tone="danger">Gateway unreachable</Status>
            ) : (
              <>
                <span className="signal">
                  Events <strong>{data?.event_count ?? "—"}</strong>
                </span>
                <span className="signal">
                  Groups <strong>{data?.group_count ?? "—"}</strong>
                </span>
                <span className="signal">
                  Drones <strong>{data?.drone_count ?? "—"}</strong>
                </span>
              </>
            )}
            <Button
              variant="ghost"
              size="icon"
              className="theme-toggle"
              onClick={toggleTheme}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
            >
              {theme === "dark" ? <Sun /> : <Moon />}
            </Button>
          </div>
        </header>
        <main className="main-canvas">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
