# Sovereign user guide

Sovereign builds small apps on your Mac from requests written in plain words. The AI runs on your Mac, so what you type and make stays there.

## Install

You need a Mac with Apple silicon (M1 or later), 8 GB of memory, and about 23 GB of free disk space.

Open Terminal and paste:

```sh
curl -fsSL https://raw.githubusercontent.com/Rohitrajsaji/Sovereign/main/install.sh | sh
```

Sovereign opens in your browser. From then on, open it from Spotlight or Launchpad like any app (it lives in your Applications folder), or type `sovereign` in Terminal. It keeps running in the background, so a closed browser tab doesn't stop work in progress.

## First run

Setup has three steps:

1. **Welcome.** What Sovereign does.
2. **Getting ready.** Sovereign checks your Mac.
   - If Apple's Command Line Tools are missing, choose **Install**. Follow Apple's installer, then choose **Check again**. Sovereign uses them to keep your project's history and to run checks.
   - Choose **Download** for the AI model (about 2.5 GB, once). You can pause and resume. If the connection drops, it continues where it stopped.
3. **Your first project.** Either:
   - start a new one: Sovereign makes a folder under **Sovereign Projects** in your home folder; or
   - choose a folder you already have. Before using it, Sovereign shows how many files it would save in the folder's history and points out files that may be private, like `.env`, and you decide. A folder with just your app works best.

You can choose **Set up later** and look around first. Requests wait until setup is finished.

## Making something

Type what you want in the box at the bottom and press Enter. Start small and add to it:

- "A to-do list that remembers my tasks"
- "Make the add button bigger and green"
- "Add a total at the bottom"

Each request gets a card that shows where it is: **Planning → Building → Checking → Done**. The card shows the current step, a progress bar, and a sentence about what's happening. One request runs at a time; new ones wait their turn.

When a request is done, its card lists the files that changed.

- **Open preview** shows your app on the right.
- **Undo** takes the change back. If another request is running, the Undo waits and happens as soon as that request finishes.

Every change, including your own edits between requests, is saved in the project's history. Undo never loses anything else.

## The panel on the right

- **Preview** shows your app as it is in the project folder. It reloads when a change lands. **Open in new tab** opens it on its own. The preview runs separately from Sovereign and can't reach it.
- **Files** lists the project's files. Choose one to read it.
- **Details** shows what happened for a request, step by step, plus technical facts for anyone who wants them.

## When Sovereign needs you

- **Needs your answer.** Sovereign asks before anything outside your project, such as downloading a package or using the internet. Read what it wants to do, then choose **Allow** or **Don't allow**. Nothing happens until you choose, and every request is asked separately.
- **Not applied yet.** The result is finished, but your folder has unsaved changes to the same files. Save or set aside those changes, then choose **Apply**. The result is kept until you do.
- **Didn't finish.** Choose **Try again**, or ask differently or in smaller steps.
- **Stop / Cancel.** Stops a request after you confirm. Nothing in your project changes.

## Troubleshooting

**"Sovereign isn't running" or "This page needs a fresh link."** Open Sovereign from Spotlight or Launchpad, or type `sovereign` in Terminal. That restarts it if needed and opens a fresh page.

**"Waiting for memory."** The AI model needs several gigabytes of free memory, and the card says roughly how much more it needs. Close apps and browser tabs you aren't using; Sovereign tries again on its own.
- When it is less than 1 GB short, **Start anyway** starts it now for that request. Your Mac may slow down while it works.
- When it is further short, choose a smaller model in **Settings → AI model**.
- After a few runs Sovereign measures the model's real memory use, and the requirement often drops.

**"Having trouble."** Sovereign hit a problem and keeps retrying. The card says why in plain words, and Details shows the exact message.
- "The AI model isn't set up yet": open **Settings → Set up** and finish the download.
- "Safety sandbox isn't available": Sovereign needs macOS on Apple silicon.

**Apple's Command Line Tools won't install.** Open **System Settings → General → Software Update** and install any updates. Then run `xcode-select --install` in Terminal, and choose **Check again** in Sovereign.

**The model download keeps failing.** Check your internet connection and choose **Try again**. It continues where it stopped. Sovereign only accepts the file if it matches its published checksum, so a damaged download is thrown away rather than used.

**A request keeps failing.** A model small enough to run on a laptop is good at small, clear requests. Split a big idea into several smaller ones, or describe the result you want to see. If you use a smaller model, a larger one in **Settings → AI model** may do better.

**A file is "too big for Sovereign to read."** Sovereign reads files up to 12 KB when it plans a change. Larger files still work in your app, but changes to them may not work well. Ask for new features in separate files, for example "put the chart in its own file".

**The same problem is still there after pulling new code.** `git pull` changes the source folder only. Run `./scripts/install-from-source.sh` to build, install, and restart Sovereign. `sovereign` also tells you when your source folder has code that isn't installed yet.

## Settings

- **AI model:** a card for each model Sovereign offers, with its download size and the memory it works best with.
  - **Download and use** fetches a model and switches to it. **Use this model** switches to one already downloaded. **Remove** frees its disk space.
  - When a request is running, Sovereign asks whether to switch **After it finishes** or to **Stop it and start again** on the new model.
  - Macs with 8 GB of memory start with **Qwen3 1.7B** (a 1.8 GB download). Macs with 16 GB or more start with **Qwen3 4B**, which builds better apps. Either Mac can switch to the other.
- **Work:** **Pause work** stops Sovereign from starting anything new; **Resume work** continues.
- **Notifications:** hear when a request finishes or needs you while the tab is in the background.
- **Advanced:**
  - the version that is running;
  - diagnostics for every check;
  - your own model files (a `llama-server` program and a `.gguf` model);
  - the name recorded with your approvals.

## Update or remove

```sh
sovereign update      # installs the newest release
sovereign uninstall   # removes Sovereign; your project folders stay
```

`sovereign uninstall` asks before deleting downloaded models and Sovereign's records of your projects. It never deletes your project folders.

## For developers

Sovereign's projects are ordinary Git repositories. A folder that already has Git history is used as it is. Sovereign never commits your own work in it, and it asks you to save or set aside changes before applying a result.

- To build from source, see the README.
- For how it works, see [docs/wiki](wiki/README.md).
- The command-line interface is in `sovereign help`.
