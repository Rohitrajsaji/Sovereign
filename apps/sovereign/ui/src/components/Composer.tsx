// Callers: the workspace's main column.
// API: `Composer`: the request box. Enter sends, Shift+Enter adds a line. `Examples` offers
// starting points for an empty project.
// Schema: POST /v2/goals. The person's words are sent as typed and never interpreted here.

import { ArrowUp } from "lucide-react";
import type { KeyboardEvent } from "react";
import { useEffect, useRef } from "react";
import { isQueued, useSubmitGoal } from "../api/query";
import { EXAMPLE_REQUESTS, GOAL_LIMIT } from "../lib/words";
import { InlineError } from "./ui";

export function Composer({
  value,
  onChange,
  busyNote,
  onSent,
}: {
  value: string;
  onChange: (value: string) => void;
  /** Why a new request will wait, when something is already running. */
  busyNote: string | null;
  onSent: (message: string | null) => void;
}) {
  const submit = useSubmitGoal();
  const field = useRef<HTMLTextAreaElement>(null);
  const text = value.trim();
  const tooLong = value.length > GOAL_LIMIT;

  useEffect(() => {
    const element = field.current;
    if (element) {
      element.style.height = "auto";
      element.style.height = `${Math.min(element.scrollHeight, 180)}px`;
    }
  }, [value]);

  const send = () => {
    if (!text || tooLong || submit.isPending) {
      return;
    }
    submit.mutate(text, {
      onSuccess: (result) => {
        onChange("");
        onSent(isQueued(result) ? result.message : null);
      },
    });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && !event.shiftKey && !event.nativeEvent.isComposing) {
      event.preventDefault();
      send();
    }
  };

  return (
    <div className="composer">
      <form
        className="composer-box"
        onSubmit={(event) => {
          event.preventDefault();
          send();
        }}
      >
        <label className="visually-hidden" htmlFor="composer">
          Describe what you want
        </label>
        <textarea
          id="composer"
          ref={field}
          className="textarea"
          rows={1}
          placeholder="Describe what you want to build or change…"
          value={value}
          onChange={(event) => onChange(event.target.value)}
          onKeyDown={onKeyDown}
        />
        <div className="composer-row">
          <span className="inline-note">
            {tooLong
              ? `That's ${value.length - GOAL_LIMIT} characters too long.`
              : (busyNote ?? "Press Enter to send, Shift+Enter for a new line.")}
          </span>
          <button
            type="submit"
            className="btn btn-primary btn-icon"
            aria-label="Send"
            disabled={!text || tooLong || submit.isPending}
          >
            {submit.isPending ? <span className="spinner" aria-hidden="true" /> : <ArrowUp size={16} aria-hidden="true" />}
          </button>
        </div>
        <InlineError error={submit.error} />
      </form>
    </div>
  );
}

export function Examples({ onPick }: { onPick: (text: string) => void }) {
  return (
    <div className="empty">
      <h2>What do you want to make?</h2>
      <p className="muted">Describe it in your own words. Sovereign plans it, builds it, checks it, and shows you the result.</p>
      <ul className="examples" aria-label="Examples">
        {EXAMPLE_REQUESTS.map((example) => (
          <li key={example}>
            <button type="button" className="example" onClick={() => onPick(example)}>
              {example}
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
