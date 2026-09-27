//! Starter files for a new project, so a person who cannot code gets something that opens in a
//! browser and a check Sovereign's verifier can run from the first request.
//!
//! Callers: `projects::create_project`.
//! API: `write_starter_project`.
//!
//! The starter is a static web app: no build step, no server, no packages. `SOVEREIGN.md` tells
//! the model the project's conventions; it is repository text, so it guides but never grants
//! authority. The check uses only the Python standard library that ships with Apple's Command
//! Line Tools.

use std::fs;
use std::io;
use std::path::Path;

fn escape_html(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn index_html(name: &str) -> String {
    let title = escape_html(name);
    format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>
    <link rel="stylesheet" href="styles.css" />
  </head>
  <body>
    <main class="app">
      <h1>{title}</h1>
      <p class="hint">Describe what you want in Sovereign, and it will build it here.</p>
    </main>
    <script src="app.js"></script>
  </body>
</html>
"#
    )
}

const STYLES_CSS: &str = r":root {
  color-scheme: light dark;
  --text: #1d1d1f;
  --muted: #6e6e73;
  --surface: #ffffff;
  --accent: #0a66ff;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
}

@media (prefers-color-scheme: dark) {
  :root {
    --text: #f5f5f7;
    --muted: #a1a1a6;
    --surface: #1c1c1e;
  }
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  background: var(--surface);
  color: var(--text);
  line-height: 1.5;
}

.app {
  max-width: 720px;
  margin: 0 auto;
  padding: 48px 24px;
}

.hint {
  color: var(--muted);
}
";

const APP_JS: &str = "// Behavior for the app goes here. It runs when index.html opens.\n";

const TEST_SITE_PY: &str = r##""""Checks that run after every change Sovereign makes to this project.

Run them with: python3 -m unittest discover -s tests
"""

import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class _References(HTMLParser):
    def __init__(self):
        super().__init__()
        self.title = ""
        self._in_title = False
        self.local_files = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "title":
            self._in_title = True
        for key in ("src", "href"):
            value = attributes.get(key)
            if value and not value.startswith(("http:", "https:", "data:", "mailto:", "#", "//")):
                self.local_files.append(value.split("?")[0].split("#")[0])

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data


class SiteTest(unittest.TestCase):
    def setUp(self):
        self.index = ROOT / "index.html"
        self.assertTrue(self.index.is_file(), "index.html must exist")
        self.references = _References()
        self.references.feed(self.index.read_text(encoding="utf-8"))

    def test_page_has_a_title(self):
        self.assertTrue(self.references.title.strip(), "index.html needs a <title>")

    def test_every_local_file_the_page_uses_exists(self):
        for reference in self.references.local_files:
            with self.subTest(reference=reference):
                self.assertTrue((ROOT / reference).is_file(), f"{reference} is missing")


if __name__ == "__main__":
    unittest.main()
"##;

fn sovereign_md(name: &str) -> String {
    format!(
        "# {name}\n\n\
This project is a static web app that opens directly in a browser. There is no build step, no \
server, and no packages to install.\n\n\
## Files\n\n\
- `index.html`: the page structure. Every other file is loaded from here.\n\
- `styles.css`: how it looks.\n\
- `app.js`: how it behaves. Store data in `localStorage` if it must survive a reload.\n\
- `tests/`: checks that must keep passing.\n\n\
## Conventions\n\n\
- Keep every file under 10 KB, so all of it fits in what Sovereign reads while planning. Put a \
new feature in its own file (for example `chart.js`) and reference it from `index.html` with a \
relative path, instead of growing one file.\n\
- Plain HTML, CSS, and JavaScript only. No frameworks, CDNs, or network requests.\n\
- Checks: `python3 -m unittest discover -s tests` must pass. Add a small test in `tests/` for new \
behavior when practical.\n"
    )
}

fn readme_md(name: &str) -> String {
    format!(
        "# {name}\n\n\
Made with Sovereign. Open `index.html` in your browser to use it.\n\n\
Every change Sovereign makes is saved in this folder's history, so you can undo it from the \
Sovereign app.\n"
    )
}

fn write_new(path: &Path, content: &str) -> io::Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, content)
}

/// Writes the starter files into `root`. Existing files are never overwritten.
///
/// # Errors
/// Returns an I/O error when a file cannot be written.
pub fn write_starter_project(root: &Path, name: &str) -> io::Result<()> {
    write_new(&root.join("index.html"), &index_html(name))?;
    write_new(&root.join("styles.css"), STYLES_CSS)?;
    write_new(&root.join("app.js"), APP_JS)?;
    write_new(&root.join("tests").join("test_site.py"), TEST_SITE_PY)?;
    write_new(&root.join("SOVEREIGN.md"), &sovereign_md(name))?;
    write_new(&root.join("README.md"), &readme_md(name))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sovereign-scaffold-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_nanos())
        ));
        fs::create_dir_all(&dir).unwrap_or_else(|error| panic!("{error}"));
        dir
    }

    #[test]
    fn starter_escapes_the_name_and_never_overwrites() {
        let dir = temp_dir("starter");
        fs::write(dir.join("app.js"), "mine").unwrap_or_else(|error| panic!("{error}"));
        write_starter_project(&dir, "Budget <App> & \"More\"")
            .unwrap_or_else(|error| panic!("{error}"));
        let index = fs::read_to_string(dir.join("index.html")).unwrap_or_default();
        assert!(index.contains("<title>Budget &lt;App&gt; &amp; &quot;More&quot;</title>"));
        assert_eq!(
            fs::read_to_string(dir.join("app.js")).ok().as_deref(),
            Some("mine")
        );
        assert!(dir.join("tests/test_site.py").is_file());
        assert!(dir.join("SOVEREIGN.md").is_file());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn starter_checks_pass_when_python_is_available() {
        let python = Path::new("/usr/bin/python3");
        if !python.is_file() {
            return;
        }
        let dir = temp_dir("checks");
        write_starter_project(&dir, "Checks").unwrap_or_else(|error| panic!("{error}"));
        let status = std::process::Command::new(python)
            .args(["-m", "unittest", "discover", "-s", "tests"])
            .current_dir(&dir)
            .output()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        // A missing referenced file fails the check.
        fs::remove_file(dir.join("styles.css")).unwrap_or_else(|error| panic!("{error}"));
        let failing = std::process::Command::new(python)
            .args(["-m", "unittest", "discover", "-s", "tests"])
            .current_dir(&dir)
            .output()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(!failing.status.success());
        let _ = fs::remove_dir_all(dir);
    }
}
