# Consumer v2 acceptance (CX2-T22)

The owner runs this on an Apple silicon Mac with the real model. It checks the six promises in
`output/CONSUMER_UX_AMENDMENT_v2.0.md`. Automated tests cover the same flows against the fixture
server, but only this run proves them with the real model, `sandbox-exec`, launchd, and the
macOS folder picker.

## Before you start

- Use a macOS user account that has never had Sovereign, ideally without Xcode or Command Line
  Tools, so the first-run path is exercised.
- A release must exist: see "Publishing a release" below.
- Keep a notes file. For each step record pass or fail, how long it took, and anything that
  needed explanation.

## The six checks

1. **Install with one command; open without Terminal afterwards.**
   - Paste the `curl … | sh` line from the README.
   - Sovereign opens in the browser.
   - Close the browser. Open Sovereign from Spotlight ("Sovereign") and from Launchpad. Each
     opens the app again.
   - Restart the Mac. Open it from Spotlight again.
2. **Finish setup from on-screen instructions only.**
   - Getting ready shows this Mac as ready.
   - Command Line Tools: Install opens Apple's installer. After it finishes, Check again shows it
     as done.
   - Download: progress moves. Pause, then Resume, continues where it stopped.
   - Turn Wi-Fi off during the download: the card explains the failure. Turn Wi-Fi on and Try
     again: it resumes.
   - Continue unlocks only when everything is ready.
3. **Create a project, ask for a small app, watch progress, see the result.**
   - New project "Tip calculator". Ask: "A tip calculator that splits a bill between friends".
   - The card moves through Planning, Building, Checking, Done with a sentence at each stage.
   - Done lists the changed files. Open preview shows a working calculator.
4. **Cancel a request; a later request then runs.**
   - Ask for a change, then choose Stop and confirm. The card reads Cancelled within a few
     seconds.
   - Ask for another change: it runs to Done.
5. **A failed request is explained in plain words; a later request then runs.**
   - Ask for something a local model can't do ("Sync my tasks with my Google Calendar").
   - The card reads Didn't finish with a plain sentence.
   - Try again, or a new small request, runs.
6. **Undo returns the folder to its previous state.**
   - On a Done card, choose Undo. The card reads Undone and the preview reloads without the
     change.
   - In Finder, the project's files match the state before the request.

## Also check

- Models, on an 8 GB Mac:
  - Setup downloads the smaller model.
  - **Settings → AI model** lists every model with its size and memory.
  - **Download and use** the larger model while a request runs: Sovereign asks. **After it finishes** keeps the running request on the old model; the next request uses the new one.
  - **Stop it and start again** restarts the request on the new model.
  - **Remove** a model that is not in use: its file leaves `~/Library/Application Support/Sovereign/models/`.
- Memory: with the larger model on 8 GB, open apps until requests wait for memory.
  - The card says about how much more memory is needed, in GB.
  - When it is less than 1 GB short, **Start anyway** asks, then starts the request.
- Folders: choose your Documents folder. Sovereign shows the file count, size, and any private-looking files, and saves nothing until you choose **Use this folder**. **Choose another** leaves the folder untouched.
- Undo while another request runs: the card says Undo will happen when that request finishes. Once it does, the change is undone.
- Big files: grow `index.html` past 12 KB. The Files tab marks it, and a notice above the message box explains.
- Versions: after `git pull` without reinstalling, `sovereign` says the source folder has code that isn't installed. After `./scripts/install-from-source.sh`, **Settings → Advanced** shows the new version.

- Edit a file in the project folder by hand, then ask for a change to the same file. The result
  lands on top of your edit, and your edit is kept.
- Open a folder that is already a Git repository with uncommitted changes. Ask for a change to a
  file you edited. The result shows **Not applied yet**, and your edit is untouched. Commit your
  edit, then Apply: it lands.
- Approvals: ask for something that needs the network ("Add a package to parse dates"). An
  approval card explains the action; Don't allow is respected.
- Settings, then Pause work: nothing new starts. Resume work continues.
- Dark mode (System Settings → Appearance) looks right.
- Keyboard only: Tab reaches every control with a visible focus ring. Escape closes dialogs.

## Automated gates to run first

```sh
./scripts/verify.sh      # Rust fmt, clippy, tests, and the UI gate
./scripts/e2e.sh         # Playwright journey against the fixture server
```

## Publishing a release

Releases are what `install.sh` and `sovereign update` download.

1. Set the version in the workspace `Cargo.toml` (`[workspace.package] version`), for example
   `0.2.0`, and commit.
2. Make the repository public. `install.sh` downloads anonymously.
3. Tag and push: `git tag v0.2.0 && git push origin v0.2.0`.
4. The `release` workflow builds on a macOS arm64 runner. It bundles the pinned llama.cpp
   runner, checks that the tag matches the Cargo version, and uploads
   `sovereign-macos-arm64.tar.gz` and `SHA256SUMS`.
5. On a Mac, run the install line from the README and do the checks above.
