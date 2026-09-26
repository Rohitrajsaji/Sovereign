# Sovereign

Sovereign builds small apps on your Mac from plain-language requests, using an AI model that runs entirely on your computer. Nothing you type or make leaves your machine.

You describe what you want ("a page that tracks my monthly budget"). Sovereign plans the work, makes the changes in a project folder, checks them, and saves every change in the project's history so you can undo it with one click.

## What you need

- A Mac with Apple silicon (M1 or later) and at least 8 GB of memory.
- About 23 GB of free disk space: 2.5 GB for the model and room to work.
- An internet connection for the first setup only.

## Install

Open Terminal and paste:

```sh
curl -fsSL https://raw.githubusercontent.com/Rohitrajsaji/Sovereign/main/install.sh | sh
```

Sovereign opens in your browser. The first time, it checks your Mac, installs Apple's free Command Line Tools if they are missing, and downloads the local model. After that, open it any time by typing `sovereign` in Terminal.

The installer puts everything under `~/.sovereign` and needs no administrator password. It checks every download against its published checksum.

## Update or remove

```sh
sovereign update      # install the newest release
sovereign uninstall   # remove Sovereign; your project folders stay
```

## Build from source

With [Rust](https://rustup.rs) installed:

```sh
git clone https://github.com/Rohitrajsaji/Sovereign.git
cd Sovereign
scripts/install-from-source.sh
```

## How it keeps your work safe

- The model only proposes. A separate controller decides what runs, checks the result, and records every step, so a model can never mark its own work as done.
- Changes are made in a private copy first and reach your folder only after they pass their checks.
- Your own edits are never overwritten. If a result would overwrite unsaved changes, Sovereign keeps it and asks you first.

## Learn more

- [User guide](docs/user-guide.md)
- [How Sovereign works](docs/wiki/README.md), for developers
