# Sovereign user guide

Install the local binary, then operate from the loopback UI.

## Install

```sh
cargo install --path apps/sovereign
```

You need `/usr/bin/git`, `/usr/bin/python3`, and `/usr/bin/sandbox-exec` on macOS. The local model is Qwen3-4B-Q4_K_M plus `llama-server`. Point Settings at those files, or set `SOVEREIGN_MODEL_RUNTIME` and `SOVEREIGN_MODEL_PATH`.

## First run

```sh
sovereign app
```

That starts `sovereign serve --execute` through a LaunchAgent if needed and opens `http://127.0.0.1:7777/?t=<token>`. Or run `sovereign serve --execute 127.0.0.1:7777` yourself and open the printed URL.

Complete onboarding: doctor checks, choose existing model files, paste a git repository path.

## Goals

Type a bounded engineering goal. Sovereign queues it. The Controller compiles and executes. Verification, not the model, marks work complete.

Pause and resume from Home. Cancel from the goal page. Cancel does not roll back git work. A dispatched action without a receipt is `unknown`.

## Approvals

Publication, spending, secret use, and destructive external actions still need an explicit Approve or Deny. There is no bulk approve.

## Recovery

If mutation is blocked, open Recovery. Unknown actions are not replayed. Conflicted worktrees are yours to fix. Sovereign will not reset your repository.

## First-run checklist

With model files already on disk, a first-time operator should be able to:

1. Finish onboarding in under 10 minutes.
2. Submit a goal and understand every status without reading logs.
3. Approve or deny one action and see exactly what will run.
4. Recover the same goal after a forced process restart, with no replay of an unknown action.

## Uninstall

```sh
sovereign service uninstall
```

Then remove `~/Library/Application Support/Sovereign/` if you want local settings gone.
