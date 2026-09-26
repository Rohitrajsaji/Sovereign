// Callers: onboarding's last step and the "New project" dialog.
// API: `ProjectChooser`: start a new project by name, or adopt a folder through the Mac's
// folder picker (with a typed path when the picker is unavailable).
// Schema: POST /v2/projects/create, POST /v2/projects/open.

import { FolderOpen } from "lucide-react";
import { useState } from "react";
import { useCreateProject, useOpenFolder } from "../api/query";
import { Button, InlineError } from "./ui";

export function ProjectChooser({ onDone }: { onDone: () => void }) {
  const [name, setName] = useState("My first app");
  const [folder, setFolder] = useState("");
  const create = useCreateProject();
  const open = useOpenFolder();
  // Once the folder picker fails (it needs a Mac desktop session), offer a typed path instead.
  const [typePath, setTypePath] = useState(false);
  const openingPicker = open.isPending && open.variables === undefined;
  const openingPath = open.isPending && open.variables !== undefined;
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
        <div className="choice-row">
          <Button
            busy={openingPicker}
            onClick={() =>
              open.mutate(undefined, {
                onSuccess: (result) => {
                  if (!result.cancelled) {
                    onDone();
                  }
                },
                onError: () => setTypePath(true),
              })
            }
          >
            <FolderOpen size={16} aria-hidden="true" />
            Choose a folder…
          </Button>
        </div>
        {typePath ? (
          <form
            className="field"
            onSubmit={(event) => {
              event.preventDefault();
              open.mutate(folder.trim(), { onSuccess: onDone });
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
              <Button type="submit" busy={openingPath} disabled={!folder.trim()}>
                Open
              </Button>
            </div>
          </form>
        ) : null}
        <InlineError error={open.error} />
      </div>
    </div>
  );
}
