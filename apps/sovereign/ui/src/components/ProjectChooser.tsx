// Callers: onboarding's last step and the "New project" dialog.
// API: `ProjectChooser`: start a new project by name, or adopt a folder through the Mac's
// folder picker (with a typed path when the picker is unavailable). Before a folder is adopted
// the person sees what that means (how much would be saved, private-looking files, a bigger
// project around it) and confirms.
// Schema: POST /v2/projects/create, POST /v2/projects/inspect, POST /v2/projects/open.

import { FolderOpen } from "lucide-react";
import { useState } from "react";
import type { FolderSummary } from "../api/generated";
import { useCreateProject, useInspectFolder, useOpenFolder } from "../api/query";
import { folderSentences, homeRelative } from "../lib/words";
import { Button, InlineError } from "./ui";

function FolderConfirm({
  summary,
  busy,
  onUse,
  onBack,
}: {
  summary: FolderSummary;
  busy: boolean;
  onUse: (root: string) => void;
  onBack: () => void;
}) {
  const target = summary.parent_project ?? summary.root ?? "";
  const warn = summary.private_files.length > 0 || summary.large;
  return (
    <div className={`folder-confirm${warn ? " folder-confirm-warn" : ""}`} role="group" aria-label="Use this folder?">
      <p>
        <strong>{summary.name ?? homeRelative(target)}</strong>{" "}
        <span className="subtle">{homeRelative(summary.root ?? "")}</span>
      </p>
      {folderSentences(summary).map((sentence) => (
        <p key={sentence} className="muted">
          {sentence}
        </p>
      ))}
      <div className="choice-row">
        <Button variant="primary" busy={busy} onClick={() => onUse(target)}>
          {summary.parent_project ? `Use ${homeRelative(summary.parent_project)}` : "Use this folder"}
        </Button>
        <Button variant="ghost" onClick={onBack}>
          Choose another
        </Button>
      </div>
    </div>
  );
}

export function ProjectChooser({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("My first app");
  const [folder, setFolder] = useState("");
  const create = useCreateProject();
  const inspect = useInspectFolder();
  const open = useOpenFolder();
  // Once the folder picker fails (it needs a Mac desktop session), offer a typed path instead.
  const [typePath, setTypePath] = useState(false);
  const [summary, setSummary] = useState<FolderSummary | null>(null);
  const openingPicker = inspect.isPending && inspect.variables === undefined;
  const checkingPath = inspect.isPending && inspect.variables !== undefined;
  const look = (root?: string) =>
    inspect.mutate(root, {
      onSuccess: (result) => {
        if (!result.cancelled) {
          setSummary(result);
        }
      },
      onError: () => {
        if (root === undefined) {
          setTypePath(true);
        }
      },
    });
  return (
    <div className="choice-grid">
      <form
        className="choice"
        onSubmit={(event) => {
          event.preventDefault();
          create.mutate(name.trim(), { onSuccess: onDone });
        }}
      >
        <h2>Start something new</h2>
        <p className="muted">Sovereign makes a folder for it in your home folder, under Sovereign Projects.</p>
        <div className="choice-row">
          <label className="visually-hidden" htmlFor="project-name">
            Project name
          </label>
          <input
            id="project-name"
            className="input"
            value={name}
            maxLength={60}
            onChange={(event) => setName(event.target.value)}
          />
          <Button type="submit" variant="primary" busy={create.isPending} disabled={!name.trim()}>
            Create
          </Button>
        </div>
        <InlineError error={create.error} />
      </form>
      <div className="choice">
        <h2>Use a folder you already have</h2>
        <p className="muted">Sovereign works inside it and keeps a history of every change.</p>
        {summary ? (
          <FolderConfirm
            summary={summary}
            busy={open.isPending}
            onUse={(root) => open.mutate(root, { onSuccess: onDone })}
            onBack={() => {
              setSummary(null);
              open.reset();
            }}
          />
        ) : (
          <>
            <div className="choice-row">
              <Button busy={openingPicker} onClick={() => look()}>
                <FolderOpen size={16} aria-hidden="true" />
                Choose a folder…
              </Button>
            </div>
            {typePath ? (
              <form
                className="field"
                onSubmit={(event) => {
                  event.preventDefault();
                  look(folder.trim());
                }}
              >
                <label className="field-label" htmlFor="folder-path">
                  Or type the folder's full path
                </label>
                <div className="choice-row">
                  <input
                    id="folder-path"
                    className="input"
                    placeholder="/Users/you/Documents/my-app"
                    value={folder}
                    onChange={(event) => setFolder(event.target.value)}
                  />
                  <Button type="submit" busy={checkingPath} disabled={!folder.trim()}>
                    Open
                  </Button>
                </div>
              </form>
            ) : null}
          </>
        )}
        <InlineError error={inspect.error ?? open.error} />
      </div>
    </div>
  );
}
