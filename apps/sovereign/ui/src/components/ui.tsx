// Callers: every SPA screen and Vitest component tests.
// API: keyboard-operable primitives with visible focus. Dialog/ConfirmDialog use Radix.
// Schema: none. Untrusted text is a text node. Inner-HTML assignment is banned.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. Components in src/components/, all keyboard-operable with visible focus.

import * as DialogPrimitive from "@radix-ui/react-dialog";
import * as TabsPrimitive from "@radix-ui/react-tabs";
import * as TooltipPrimitive from "@radix-ui/react-tooltip";
import {
  Activity,
  FolderGit2,
  Home,
  Settings,
  ShieldAlert,
  Stethoscope,
  Target,
  X,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { ButtonHTMLAttributes, CSSProperties, ReactNode } from "react";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { NavLink } from "react-router-dom";
import { tokenize } from "../lib/tokenizer";
import { statusTone } from "../lib/status";

export function Button({
  variant = "primary",
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "danger" | "ghost" }) {
  return <button className={`sv-btn sv-btn-${variant} ${className}`} {...rest} />;
}

export function IconButton({
  label,
  className = "",
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return <button className={`sv-btn sv-btn-ghost sv-icon-btn ${className}`} aria-label={label} {...rest} />;
}

export function StatusPill({ status }: { status: string }) {
  return <span className={`sv-pill sv-pill-${statusTone(status)}`}>{status}</span>;
}

export function Card({
  title,
  eyebrow,
  children,
}: {
  title: string;
  eyebrow?: string;
  children: ReactNode;
}) {
  return (
    <section className="sv-card">
      {eyebrow ? <p className="sv-eyebrow">{eyebrow}</p> : null}
      <h2>{title}</h2>
      {children}
    </section>
  );
}

export function EmptyState({ title, detail }: { title: string; detail: string }) {
  return (
    <div className="sv-empty" role="status">
      <strong>{title}</strong>
      <p>{detail}</p>
    </div>
  );
}

export function Skeleton({ label = "Loading" }: { label?: string }) {
  return (
    <div className="sv-skeleton" role="status" aria-live="polite">
      {label}
    </div>
  );
}

export function ErrorState({ message }: { message: string }) {
  return (
    <p className="sv-error" role="alert">
      {message}
    </p>
  );
}

export function OfflineState() {
  return (
    <p className="sv-error" role="alert">
      The local Controller is unreachable. Confirm `sovereign serve` is running on loopback.
    </p>
  );
}

export function Toast({ message }: { message: string }) {
  return (
    <div className="sv-toast" role="status" aria-live="polite">
      {message}
    </div>
  );
}

export function Dialog({
  open,
  title,
  children,
  onClose,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  onClose: () => void;
}) {
  const titleId = useId();
  return (
    <DialogPrimitive.Root open={open} onOpenChange={(next) => !next && onClose()}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="sv-dialog-backdrop" />
        <DialogPrimitive.Content className="sv-dialog" aria-labelledby={titleId}>
          <DialogPrimitive.Title id={titleId} className="sv-dialog-title">
            {title}
          </DialogPrimitive.Title>
          {children}
          <DialogPrimitive.Close asChild>
            <Button variant="ghost">
              <CloseIcon /> Close
            </Button>
          </DialogPrimitive.Close>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}

export function ConfirmDialog({
  open,
  title,
  children,
  onClose,
  onConfirm,
  confirmLabel,
  confirmDisabled = false,
}: {
  open: boolean;
  title: string;
  children: ReactNode;
  onClose: () => void;
  onConfirm: () => void;
  confirmLabel: string;
  confirmDisabled?: boolean;
}) {
  return (
    <Dialog open={open} title={title} onClose={onClose}>
      {children}
      <div className="sv-row">
        <Button variant="danger" onClick={onConfirm} disabled={confirmDisabled}>
          {confirmLabel}
        </Button>
      </div>
    </Dialog>
  );
}

export function Tabs({
  tabs,
  active,
  onChange,
}: {
  tabs: readonly string[];
  active: string;
  onChange: (tab: string) => void;
}) {
  return (
    <TabsPrimitive.Root value={active} onValueChange={onChange}>
      <TabsPrimitive.List className="sv-tabs" aria-label="Goal sections">
        {tabs.map((tab) => (
          <TabsPrimitive.Trigger key={tab} value={tab} className="sv-tab">
            {tab}
          </TabsPrimitive.Trigger>
        ))}
      </TabsPrimitive.List>
      {tabs.map((tab) => (
        <TabsPrimitive.Content key={`${tab}-panel`} value={tab} className="sv-tab-panel">
          <span className="sv-sr-only">{tab} panel</span>
        </TabsPrimitive.Content>
      ))}
    </TabsPrimitive.Root>
  );
}

export function Tooltip({ text, children }: { text: string; children: ReactNode }) {
  return (
    <TooltipPrimitive.Provider delayDuration={120}>
      <TooltipPrimitive.Root>
        <TooltipPrimitive.Trigger asChild>{children}</TooltipPrimitive.Trigger>
        <TooltipPrimitive.Portal>
          <TooltipPrimitive.Content className="sv-tooltip" sideOffset={6}>
            {text}
          </TooltipPrimitive.Content>
        </TooltipPrimitive.Portal>
      </TooltipPrimitive.Root>
    </TooltipPrimitive.Provider>
  );
}

export function CodeBlock({ text }: { text: string }) {
  return (
    <pre className="sv-code">
      <code>
        {tokenize(text).map((token, index) => (
          <span key={`${index}-${token.kind}`} className={`tok-${token.kind}`}>
            {token.text}
          </span>
        ))}
      </code>
    </pre>
  );
}

export function DiffViewer({ diff }: { diff: string }) {
  return (
    <pre className="sv-diff" aria-label="Unified diff">
      {diff.split("\n").map((line, index) => (
        <span
          key={`${index}-${line.slice(0, 24)}`}
          className={line.startsWith("+") ? "add" : line.startsWith("-") ? "del" : ""}
        >
          {line}
          {"\n"}
        </span>
      ))}
    </pre>
  );
}

export function KeyValue({ items }: { items: Array<[string, string]> }) {
  return (
    <dl className="sv-kv">
      {items.map(([key, value]) => (
        <div key={key} className="sv-kv-row">
          <dt>{key}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Timeline({
  items,
}: {
  items: Array<{ id: string; title: string; detail: string; raw?: string }>;
}) {
  return (
    <ol className="sv-timeline">
      {items.map((item) => (
        <li key={item.id}>
          <strong>{item.title}</strong>
          <p className="sv-muted">{item.detail}</p>
          {item.raw ? (
            <details>
              <summary>Raw event</summary>
              <CodeBlock text={item.raw} />
            </details>
          ) : null}
        </li>
      ))}
    </ol>
  );
}

export function ProgressRing({ value }: { value: number }) {
  const clamped = Math.max(0, Math.min(100, value));
  return (
    <span
      className="sv-ring"
      role="meter"
      aria-label="Progress"
      aria-valuenow={clamped}
      aria-valuemin={0}
      aria-valuemax={100}
      style={{ "--progress": clamped } as CSSProperties}
    >
      <span>{clamped}%</span>
    </span>
  );
}

const NAV: Array<[string, string, LucideIcon]> = [
  ["/", "Home", Home],
  ["/projects", "Projects", FolderGit2],
  ["/goals", "Goals", Target],
  ["/approvals", "Approvals", ShieldAlert],
  ["/recovery", "Recovery", Activity],
  ["/settings", "Settings", Settings],
  ["/diagnostics", "Diagnostics", Stethoscope],
];

export function AppShell({
  children,
  message,
  onOpenPalette,
}: {
  children: ReactNode;
  message: string;
  onOpenPalette: () => void;
}) {
  const offline = /offline|did not answer|unreachable/i.test(message);
  return (
    <div className="sv-shell">
      <aside className="sv-nav">
        <div className="sv-brand-lockup">
          <svg className="sv-mark" viewBox="0 0 32 32" aria-hidden="true">
            <circle cx="16" cy="16" r="11" fill="none" stroke="currentColor" strokeWidth="1.6" />
            <path d="M10 17.5 14 21l8-10" fill="none" stroke="currentColor" strokeWidth="1.8" />
          </svg>
          <div>
            <p className="sv-brand">Sovereign</p>
            <p className="sv-brand-sub">Local control plane</p>
          </div>
        </div>
        <nav aria-label="Primary">
          {NAV.map(([path, label, Icon]) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) => `sv-nav-link${isActive ? " is-active" : ""}`}
              end={path === "/"}
            >
              <Icon size={16} aria-hidden="true" />
              {label}
            </NavLink>
          ))}
        </nav>
        <p className="sv-nav-foot">Loopback only. The Controller commits.</p>
      </aside>
      <div className="sv-main">
        <header className="sv-top">
          <div>
            <p className="sv-eyebrow">Controller</p>
            <h1>Sovereign</h1>
          </div>
          <div className="sv-top-meta">
            <p className={`sv-chip${offline ? " sv-chip-offline" : ""}`}>
              <span className="sv-chip-dot" aria-hidden="true" />
              {offline ? "Offline" : "Loopback"}
            </p>
            <p className="sv-muted">{message}</p>
            <Button variant="ghost" onClick={onOpenPalette} aria-keyshortcuts="Meta+K">
              Command ⌘K
            </Button>
          </div>
        </header>
        {children}
      </div>
    </div>
  );
}

export function CommandPalette({
  open,
  onClose,
  onNavigate,
}: {
  open: boolean;
  onClose: () => void;
  onNavigate: (path: string) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState("");
  const destinations = useMemo(() => {
    const extra: Array<[string, string]> = [["/welcome", "Onboarding"]];
    return [...NAV.map(([path, label]) => [path, label] as [string, string]), ...extra].filter(([, label]) =>
      label.toLowerCase().includes(query.trim().toLowerCase()),
    );
  }, [query]);
  useEffect(() => {
    if (open) {
      input.current?.focus();
      setQuery("");
    }
  }, [open]);
  return (
    <Dialog open={open} title="Jump to" onClose={onClose}>
      <label htmlFor="palette-q">Command</label>
      <input
        id="palette-q"
        ref={input}
        aria-label="Jump to"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            onClose();
          }
          if (event.key === "Enter") {
            const first = destinations[0];
            if (first) {
              onNavigate(first[0]);
              onClose();
            }
          }
        }}
      />
      <div className="sv-palette-list">
        {destinations.map(([path, label]) => (
          <Button
            key={path}
            variant="ghost"
            onClick={() => {
              onNavigate(path);
              onClose();
            }}
          >
            {label}
          </Button>
        ))}
      </div>
    </Dialog>
  );
}

export function CloseIcon() {
  return <X size={16} aria-hidden="true" />;
}
