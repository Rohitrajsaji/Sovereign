// Callers: App shell once setup is done (or deferred) and a project exists.
// API: `Workspace`: projects sidebar, the selected project's conversation and composer, and the
// Preview / Files / Details panel.
// Schema: ProjectsResponse, GoalView, OverviewResponse, SetupStatus from control-api-v2.

import { CircleHelp, PanelRightOpen, Plus, Settings } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { GoalView, SetupStatus } from "../api/generated";
import {
  isSwitchingProject,
  useActivateProject,
  useGoals,
  useOverview,
  useProjects,
  useProjectSwitchRefresh,
  useResume,
  useSettings,
} from "../api/query";
import { Composer, Examples } from "../components/Composer";
import { Conversation, useRetry } from "../components/Conversation";
import { HelpDialog, NewProjectDialog, SettingsDialog } from "../components/Dialogs";
import { ProjectChooser } from "../components/ProjectChooser";
import { SidePanel, type PanelTab } from "../components/SidePanel";
import { BrandMark, Button, IconButton, InlineError, Notice, Spinner, useToast } from "../components/ui";
import { desktopNotify, goalNotice } from "../lib/notify";

type DialogName = "settings" | "help" | "new" | null;

function serviceLine(working: boolean, paused: boolean, running: boolean, ready: boolean) {
  if (paused) {
    return { dot: "dot-warning", text: "Paused" };
  }
  if (!ready) {
    return { dot: "dot-warning", text: "Waiting for setup" };
  }
  if (working || running) {
    return { dot: "dot-working", text: "Working" };
  }
  return { dot: "dot-success", text: "Ready" };
}

/** `/Users/ana/Sovereign Projects/Budget` reads as `~/Sovereign Projects/Budget`. */
function homeRelative(path: string): string {
  return path.replace(/^\/(Users|home)\/[^/]+(?=\/|$)/, "~");
}

/** Changes whenever a result lands or is undone, so the preview and files reload. */
function resultKey(projectId: string | null | undefined, goals: GoalView[]): string {
  const latest = goals.reduce((max, goal) => Math.max(max, goal.landing?.updated_at_ms ?? 0), 0);
  return `${projectId ?? "none"}:${latest}`;
}

export function Workspace({ setup, onOpenSetup }: { setup: SetupStatus | undefined; onOpenSetup: () => void }) {
  const projects = useProjects(true);
  const goals = useGoals(true);
  const overview = useOverview(true);
  const settings = useSettings(true);
  const activate = useActivateProject();
  const resume = useResume();
  const toast = useToast();
  const [panelOpen, setPanelOpen] = useState(true);
  const [tab, setTab] = useState<PanelTab>("preview");
  const [selectedGoal, setSelectedGoal] = useState<string | undefined>(undefined);
  const [draft, setDraft] = useState("");
  const [dialog, setDialog] = useState<DialogName>(null);
  const previousGoals = useRef<GoalView[] | undefined>(undefined);

  const list = useMemo(() => goals.data ?? [], [goals.data]);
  const activeId = projects.data?.active_project_id;
  const active = projects.data?.projects.find((project) => project.project_id === activeId);
  const running = list.some((goal) => !goal.progress.terminal);
  const paused = overview.data?.paused ?? false;
  const ready = setup?.ready ?? false;
  const status = serviceLine(overview.data?.working ?? false, paused, running, ready);
  const retry = useRetry(toast);
  // Until a chosen project opens, requests and the preview still come from the previous one.
  const switching = isSwitchingProject(overview.data);
  useProjectSwitchRefresh(switching);

  useEffect(() => {
    const notice = goalNotice(previousGoals.current, list);
    previousGoals.current = goals.data ? list : previousGoals.current;
    if (notice) {
      toast(notice);
      desktopNotify(notice);
    }
  }, [goals.data, list, toast]);

  useEffect(() => {
    // A new project starts with an empty conversation and its own preview.
    previousGoals.current = undefined;
    setSelectedGoal(undefined);
  }, [activeId, switching]);

  const detailsGoal = list.find((goal) => goal.goal_id === selectedGoal) ?? list.at(-1);

  return (
    <div className={`app${panelOpen && active ? " with-panel" : ""}`}>
      <nav className="sidebar" aria-label="Projects">
        <div className="brand">
          <BrandMark />
          Sovereign
        </div>
        <Button onClick={() => setDialog("new")}>
          <Plus size={16} aria-hidden="true" />
          New project
        </Button>
        <p className="sidebar-section">Projects</p>
        <ul className="project-list">
          {(projects.data?.projects ?? []).map((project) => {
            const current = project.project_id === activeId;
            return (
              <li key={project.project_id}>
                <button
                  type="button"
                  className="project-item"
                  aria-current={current ? "true" : undefined}
                  disabled={activate.isPending}
                  onClick={() => {
                    if (!current) {
                      activate.mutate(project.project_id);
                    }
                  }}
                >
                  <span className={`dot ${current ? status.dot : ""}`} aria-hidden="true" />
                  <span className="project-name">{project.display_name}</span>
                </button>
              </li>
            );
          })}
        </ul>
        <InlineError error={activate.error} />
        <div className="sidebar-footer">
          <div className="service-line" role="status">
            <span className={`dot ${status.dot}`} aria-hidden="true" />
            {status.text}
          </div>
          <Button variant="ghost" onClick={() => setDialog("settings")}>
            <Settings size={16} aria-hidden="true" />
            Settings
          </Button>
          <Button variant="ghost" onClick={() => setDialog("help")}>
            <CircleHelp size={16} aria-hidden="true" />
            Help
          </Button>
        </div>
      </nav>

      <main className="main">
        {active ? (
          <>
            <header className="main-header">
              <div className="main-title">
                <h1>{active.display_name}</h1>
                <p title={active.root}>{homeRelative(active.root)}</p>
              </div>
              {panelOpen ? null : (
                <IconButton label="Show preview" onClick={() => setPanelOpen(true)}>
                  <PanelRightOpen size={16} aria-hidden="true" />
                </IconButton>
              )}
            </header>
            {!ready ? (
              <div className="banner-row">
                <Notice tone="warning">
                  Sovereign's AI isn't set up yet, so requests wait until it is.{" "}
                  <button type="button" className="link-button" onClick={onOpenSetup}>
                    Finish setup
                  </button>
                </Notice>
              </div>
            ) : null}
            {paused ? (
              <div className="banner-row">
                <Notice tone="warning">
                  Paused. Sovereign won't start new work.{" "}
                  <button type="button" className="link-button" onClick={() => resume.mutate()}>
                    Resume
                  </button>
                </Notice>
              </div>
            ) : null}
            {switching ? (
              <div className="conversation">
                <div className="conversation-inner">
                  <Spinner label={`Opening ${active.display_name}. Sovereign finishes its current step first.`} />
                </div>
              </div>
            ) : goals.isPending ? (
              <div className="conversation">
                <div className="conversation-inner">
                  <Spinner label="Loading this project" />
                </div>
              </div>
            ) : list.length === 0 ? (
              <div className="conversation">
                <Examples onPick={setDraft} />
              </div>
            ) : (
              <Conversation
                goals={list}
                approvals={overview.data?.blocked_approvals ?? []}
                principal={settings.data?.approval_principal ?? "operator@ui"}
                onShowPreview={() => {
                  setPanelOpen(true);
                  setTab("preview");
                }}
                onDetails={(goalId) => {
                  setSelectedGoal(goalId);
                  setPanelOpen(true);
                  setTab("details");
                }}
                onRetry={retry}
              />
            )}
            <Composer
              value={draft}
              onChange={setDraft}
              busyNote={running ? "Sovereign starts this after the current request." : null}
              onSent={(message) => {
                if (message) {
                  toast(message);
                }
              }}
            />
          </>
        ) : projects.isPending ? (
          <Spinner label="Loading" />
        ) : (
          <div className="conversation">
            <div className="empty">
              <h2>Create your first project</h2>
              <p className="muted">A project is a folder where Sovereign builds your app.</p>
            </div>
            <div className="conversation-inner">
              <ProjectChooser onDone={() => undefined} />
            </div>
          </div>
        )}
      </main>

      {panelOpen && active ? (
        <SidePanel
          tab={tab}
          onTabChange={setTab}
          onClose={() => setPanelOpen(false)}
          goal={switching ? undefined : detailsGoal}
          serviceDetail={overview.data?.service_phase === "error" ? overview.data.detail : undefined}
          reloadKey={resultKey(activeId, list)}
          opening={switching}
        />
      ) : null}

      <SettingsDialog
        open={dialog === "settings"}
        onOpenChange={(open) => setDialog(open ? "settings" : null)}
        setup={setup}
        overview={overview.data}
        onOpenSetup={() => {
          setDialog(null);
          onOpenSetup();
        }}
      />
      <HelpDialog open={dialog === "help"} onOpenChange={(open) => setDialog(open ? "help" : null)} />
      <NewProjectDialog open={dialog === "new"} onOpenChange={(open) => setDialog(open ? "new" : null)} />
    </div>
  );
}
