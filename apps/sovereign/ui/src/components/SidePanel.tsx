// Callers: the workspace, beside the conversation.
// API: `SidePanel` with three tabs: Preview (the app in a sandboxed frame on its own origin),
// Files (read-only), and Details (what happened, including technical facts).
// Schema: PreviewResponse, ProjectFilesResponse, ProjectFileContent, GoalView, GoalActivity.
// File contents, request text, and activity lines are rendered only as text nodes.

import * as TabsPrimitive from "@radix-ui/react-tabs";
import { ExternalLink, PanelRightClose, RefreshCw } from "lucide-react";
import { useState } from "react";
import type { GoalView } from "../api/generated";
import { useFileContent, useFiles, useGoalActivity, usePreview } from "../api/query";
import { clockTime, formatBytes } from "../lib/words";
import { IconButton, Spinner } from "./ui";

export type PanelTab = "preview" | "files" | "details";

function PreviewTab({ reloadKey }: { reloadKey: string }) {
  const preview = usePreview(true);
  const [manual, setManual] = useState(0);
  const url = preview.data?.url;
  if (preview.isPending) {
    return <Spinner label="Loading the preview" />;
  }
  if (!preview.data?.available || !url) {
    return (
      <div className="panel-empty">
        <strong>No preview yet</strong>
        <span>Your app appears here once the project has a page.</span>
      </div>
    );
  }
  return (
    <>
      <div className="preview-bar">
        <span className="subtle">Your app, as it is now in the project folder</span>
        <IconButton label="Reload preview" onClick={() => setManual((count) => count + 1)}>
          <RefreshCw size={15} aria-hidden="true" />
        </IconButton>
        <a className="btn btn-ghost" href={url} target="_blank" rel="noreferrer noopener">
          <ExternalLink size={15} aria-hidden="true" />
          Open in new tab
        </a>
      </div>
      {/* Its own site (localhost, not 127.0.0.1): no cookies, no access to Sovereign. */}
      <iframe
        key={`${reloadKey}:${manual}`}
        className="preview-frame"
        title="Preview of your app"
        src={url}
        sandbox="allow-scripts allow-same-origin allow-forms allow-modals"
        referrerPolicy="no-referrer"
      />
    </>
  );
}

function FilesTab() {
  const files = useFiles(true);
  const [selected, setSelected] = useState<string | undefined>(undefined);
  const current = selected ?? files.data?.files.find((file) => file.path === "index.html")?.path;
  const content = useFileContent(current);
  if (files.isPending) {
    return <Spinner label="Loading files" />;
  }
  if (files.isError) {
    return (
      <div className="panel-empty">
        <strong>Files aren't available</strong>
        <span>{files.error.message}</span>
      </div>
    );
  }
  const list = files.data?.files ?? [];
  if (list.length === 0) {
    return (
      <div className="panel-empty">
        <strong>No files yet</strong>
        <span>Files Sovereign makes appear here.</span>
      </div>
    );
  }
  return (
    <div className="files">
      <ul className="file-list" aria-label="Project files">
        {list.map((file) => (
          <li key={file.path}>
            <button
              type="button"
              className="file-item"
              aria-current={file.path === current ? "true" : undefined}
              onClick={() => setSelected(file.path)}
            >
              <span>{file.path}</span>
              <span className="subtle">{formatBytes(file.size_bytes)}</span>
            </button>
          </li>
        ))}
      </ul>
      {content.isPending && current ? (
        <Spinner label="Opening the file" />
      ) : content.data?.binary ? (
        <div className="panel-empty">This file isn't text, so it can't be shown here.</div>
      ) : content.data ? (
        // A scrollable region must be reachable from the keyboard to be scrolled (WCAG 2.1.1).
        // eslint-disable-next-line jsx-a11y/no-noninteractive-tabindex
        <pre className="file-view" aria-label={`Contents of ${content.data.path}`} tabIndex={0}>
          {content.data.text}
          {content.data.truncated ? "\n\n… (only the beginning of this file is shown)" : ""}
        </pre>
      ) : (
        <div className="panel-empty">Choose a file to see it.</div>
      )}
    </div>
  );
}

function DetailsTab({ goal, serviceDetail }: { goal: GoalView | undefined; serviceDetail?: string }) {
  const activity = useGoalActivity(goal?.goal_id);
  if (!goal) {
    return (
      <div className="panel-empty">
        <strong>Nothing to show yet</strong>
        <span>Details about each request appear here.</span>
      </div>
    );
  }
  const landing = goal.landing;
  return (
    <div className="details">
      <section>
        <h3>Request</h3>
        <p>{goal.natural_language_goal}</p>
      </section>
      <section>
        <h3>What happened</h3>
        {activity.isPending ? (
          <Spinner label="Loading" />
        ) : (activity.data ?? []).length === 0 ? (
          <p className="muted">{goal.progress.sentence}</p>
        ) : (
          <ol className="activity">
            {(activity.data ?? []).map((line) => (
              <li key={line.sequence}>
                <time dateTime={new Date(line.occurred_at_ms).toISOString()}>{clockTime(line.occurred_at_ms)}</time>
                <span>{line.text}</span>
              </li>
            ))}
          </ol>
        )}
      </section>
      <section>
        <h3>Technical details</h3>
        <dl className="facts">
          <dt>Status</dt>
          <dd>{goal.status}</dd>
          {serviceDetail && !goal.progress.terminal ? (
            <>
              <dt>Service said</dt>
              <dd className="mono">{serviceDetail}</dd>
            </>
          ) : null}
          <dt>Request id</dt>
          <dd className="mono">{goal.goal_id}</dd>
          {goal.outcome ? (
            <>
              <dt>Reason</dt>
              <dd className="mono">{goal.outcome.reason_code}</dd>
              <dt>Detail</dt>
              <dd>{goal.outcome.detail}</dd>
            </>
          ) : null}
          {landing ? (
            <>
              <dt>Result</dt>
              <dd>{landing.status.replaceAll("_", " ")}</dd>
              {landing.commit ? (
                <>
                  <dt>Saved as</dt>
                  <dd className="mono">{landing.commit.slice(0, 12)}</dd>
                </>
              ) : null}
              {landing.technical_detail ? (
                <>
                  <dt>Git said</dt>
                  <dd className="mono">{landing.technical_detail}</dd>
                </>
              ) : null}
            </>
          ) : null}
        </dl>
      </section>
    </div>
  );
}

export function SidePanel({
  tab,
  onTabChange,
  onClose,
  goal,
  serviceDetail,
  reloadKey,
}: {
  tab: PanelTab;
  onTabChange: (tab: PanelTab) => void;
  onClose: () => void;
  goal: GoalView | undefined;
  serviceDetail?: string;
  reloadKey: string;
}) {
  return (
    <aside className="panel" aria-label="Preview and details">
      <TabsPrimitive.Root
        value={tab}
        onValueChange={(value) => onTabChange(value as PanelTab)}
        className="tab-content"
      >
        <div className="tabs-list">
          <TabsPrimitive.List className="tabs" aria-label="Panel">
            <TabsPrimitive.Trigger className="tab" value="preview">
              Preview
            </TabsPrimitive.Trigger>
            <TabsPrimitive.Trigger className="tab" value="files">
              Files
            </TabsPrimitive.Trigger>
            <TabsPrimitive.Trigger className="tab" value="details">
              Details
            </TabsPrimitive.Trigger>
          </TabsPrimitive.List>
          <span className="spacer" />
          <IconButton label="Hide panel" onClick={onClose}>
            <PanelRightClose size={16} aria-hidden="true" />
          </IconButton>
        </div>
        <TabsPrimitive.Content className="tab-content" value="preview">
          <PreviewTab reloadKey={reloadKey} />
        </TabsPrimitive.Content>
        <TabsPrimitive.Content className="tab-content" value="files">
          <FilesTab key={reloadKey} />
        </TabsPrimitive.Content>
        <TabsPrimitive.Content className="tab-content" value="details">
          <DetailsTab goal={goal} serviceDetail={serviceDetail} />
        </TabsPrimitive.Content>
      </TabsPrimitive.Root>
    </aside>
  );
}
