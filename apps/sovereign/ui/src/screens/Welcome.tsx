// Callers: Hash route /welcome.
// API: onboarding wizard over /v2/doctor, /v2/settings, /v2/projects.
// Schema: DoctorResponse, SettingsV1, ProjectsResponse.
// User instruction: Continue from the current tree and finish the remaining consumer-product gaps you identified. CX-T18 onboarding wizard.

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAddProject, useDoctor, useProjects, useSettings, useVerifyModel } from "../api/query";
import { Button, Card, EmptyState, StatusPill } from "../components/ui";

const STEPS = ["Welcome", "System check", "Model", "Repository", "Service", "Done"] as const;

export function WelcomeScreen({ ready }: { ready: boolean }) {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const doctor = useDoctor(ready);
  const settings = useSettings(ready);
  const projects = useProjects(ready);
  const addProject = useAddProject();
  const verify = useVerifyModel();
  const [runtime, setRuntime] = useState("");
  const [model, setModel] = useState("");
  const [root, setRoot] = useState("");
  const [name, setName] = useState("Local repo");
  const failed = (doctor.data ?? []).some((check) => check.status === "fail");

  return (
    <Card title="Onboarding" eyebrow={`Step ${step + 1} of ${STEPS.length}`}>
      <ol className="sv-steps" aria-label="Onboarding steps">
        {STEPS.map((label, index) => (
          <li key={label} className={index === step ? "is-active" : ""}>
            {index + 1}. {label}
          </li>
        ))}
      </ol>
      {step === 0 ? (
        <>
          <p>Sovereign is a local Controller. The model proposes. Verification, not the model, decides completion.</p>
          <p className="sv-muted">
            It stays on this machine. Publication, spending, secret use, and destructive external actions still need an
            explicit approval.
          </p>
          <Button onClick={() => setStep(1)}>Continue</Button>
        </>
      ) : null}
      {step === 1 ? (
        <>
          <ul className="sv-check-list">
            {(doctor.data ?? []).map((check) => (
              <li key={check.id}>
                <StatusPill status={check.status} /> {check.id}: {check.detail} {check.fix_hint}
              </li>
            ))}
          </ul>
          <div className="sv-row">
            <Button variant="ghost" onClick={() => void doctor.refetch()}>
              Re-run checks
            </Button>
            <Button disabled={failed} onClick={() => setStep(2)} aria-describedby="onboard-reason">
              Continue
            </Button>
          </div>
          <p id="onboard-reason">
            {failed ? "Fix failing doctor checks before continuing." : "System checks passed or only warn."}
          </p>
        </>
      ) : null}
      {step === 2 ? (
        <>
          <p>Choose existing files. Download stays off because the committed manifest has no URL.</p>
          <label htmlFor="runtime">llama-server path</label>
          <input id="runtime" value={runtime} onChange={(event) => setRuntime(event.target.value)} />
          <label htmlFor="model">GGUF path</label>
          <input id="model" value={model} onChange={(event) => setModel(event.target.value)} />
          <p className="sv-muted">
            Current: {settings.data?.model_runtime ?? "not set"} / {settings.data?.model_path ?? "not set"}
          </p>
          <div className="sv-row">
            <Button
              variant="ghost"
              onClick={() =>
                void verify.mutateAsync({ runtime_path: runtime, model_path: model }).catch(() => undefined)
              }
            >
              Verify files
            </Button>
            <Button onClick={() => setStep(3)}>Continue</Button>
          </div>
        </>
      ) : null}
      {step === 3 ? (
        <>
          <p>Paste an absolute git repository path. The browser cannot open a native folder picker.</p>
          <label htmlFor="repo">Repository path</label>
          <input id="repo" value={root} onChange={(event) => setRoot(event.target.value)} />
          <label htmlFor="repo-name">Display name</label>
          <input id="repo-name" value={name} onChange={(event) => setName(event.target.value)} />
          {projects.data?.projects.length ? (
            <ul>
              {projects.data.projects.map((project) => (
                <li key={project.project_id}>
                  {project.display_name} — {project.root}
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No projects yet" detail="Register a git work tree to give the Controller a root." />
          )}
          <div className="sv-row">
            <Button
              variant="ghost"
              onClick={() => void addProject.mutateAsync({ root, display_name: name }).catch(() => undefined)}
            >
              Add repository
            </Button>
            <Button onClick={() => setStep(4)}>Continue</Button>
          </div>
        </>
      ) : null}
      {step === 4 ? (
        <>
          <p>
            The background service is optional. `sovereign service install` writes a LaunchAgent that runs `serve
            --execute` on loopback.
          </p>
          <p className="sv-muted">This UI does not install launchd jobs itself. Use the CLI so the host policy stays explicit.</p>
          <Button onClick={() => setStep(5)}>Continue</Button>
        </>
      ) : null}
      {step === 5 ? (
        <>
          <p>Ready. Queue a bounded goal: file create or patch, governed build or test, at most 16 tasks.</p>
          <Button onClick={() => navigate("/goals/new")}>Write the first goal</Button>
        </>
      ) : null}
    </Card>
  );
}
