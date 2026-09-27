# Code signing, notarization, and the first tagged release

Status: plan, 2026-09-27. Nothing here is implemented yet.

## Where things stand

- `.github/workflows/release.yml` already builds on a `v*` tag (macos-14, Rust 1.89.0), checks that `sovereign --version` matches the tag, runs `scripts/package-release.sh`, smoke-tests the tarball, and uploads `sovereign-macos-arm64.tar.gz` and `SHA256SUMS`.
- Nothing is signed. The `sovereign` binary carries only the linker's ad-hoc signature. `llama-server` and its dylibs ship exactly as upstream built them.
- No tag and no GitHub release exist. The repository is public, so `install.sh` and `sovereign update` (both read `releases/latest/download`) will work as soon as one non-prerelease release is published. Today they 404.
- The workspace version is `0.1.0` (`Cargo.toml`), shared by every crate.
- `output/CONSUMER_UX_AMENDMENT_v1.0.md` puts signed distribution and auto-update out of scope. `docs/plans/consumer-production-readiness.md` Phase 1 calls for a new amendment before this work lands.

### Why signing matters even though `curl` downloads are not quarantined

`install.sh` and `sovereign update` fetch with `/usr/bin/curl`, which sets no `com.apple.quarantine` attribute, so Gatekeeper does not block the unsigned binary today (`docs/plans/consumer-v2-plan.md`). That stops being true the moment someone downloads the tarball in a browser, AirDrops it, or we ship a `.pkg` or DMG. Signing also gives a stable code identity, which the privacy prompts macOS shows for folders like Documents and Desktop key on. An ad-hoc identity changes with every build, so every update re-prompts.

## The one design problem: the pinned runner hash

`apps/sovereign/src/model_setup.rs:680` (`bundled_runtime`) accepts `libexec/llama/llama-server` only if its SHA-256 equals `runtime.executable_sha256` in `apps/sovereign/assets/model-manifest-v2.json` (the upstream `d0878274…`). Notarization requires every Mach-O in the submission to be signed with our Developer ID, the hardened runtime, and a secure timestamp. Re-signing `llama-server` rewrites its signature, so its hash changes and `bundled_runtime` silently rejects the bundled copy. Sovereign then falls back to downloading the unsigned upstream runner.

Recommendation: keep the upstream hash pin for downloaded runners, and accept the bundled runner by code signature instead.

1. Add a `SOVEREIGN_TEAM_ID` compile-time constant (from `option_env!`, set by the release workflow; absent in dev builds).
2. In `bundled_runtime`, when the constant is set, run `/usr/bin/codesign --verify --strict -R '=anchor apple generic and certificate leaf[subject.OU] = "<TEAM_ID>"'` on the bundled runner and accept it on success. Otherwise fall back to today's hash check, so dev builds and tests behave as now.
3. Unit-test both branches with a fake `codesign` runner, the same way `launch_agent.rs` fakes `launchctl`.

The alternative is to sign the runner before `cargo build` and bake the signed hash into the binary through `build.rs`. It keeps a pure hash check but makes the build order fragile, and a timestamped re-sign changes the hash again.

## Signing and notarization in CI

A new step in `release.yml`, between "Build sovereign" and "Package", runs only when the signing secrets exist. Forks and dry runs still produce an unsigned build.

1. Import the Developer ID Application certificate into a temporary keychain created for the job and deleted at the end.
2. Sign the runner's dylibs first, then `llama-server`, then `sovereign`, each with `codesign --force --options runtime --timestamp --sign "Developer ID Application: … (TEAM_ID)"`.
   - Start with no entitlements. With the hardened runtime, library validation requires `llama-server`'s dylibs to carry the same Team ID, which step 2 gives them.
   - Add `com.apple.security.cs.disable-library-validation` only if a Mac test proves it is needed.
   - `sovereign` spawns `/usr/bin/sandbox-exec`, `git`, and Chrome as child processes, which the hardened runtime does not restrict. Signing must not change the sandbox profiles (AGENTS.md: do not weaken `sandbox-exec`).
3. Move signing into `scripts/package-release.sh` (behind an optional `SIGN_IDENTITY` variable), because that script is what copies the runner folder. The workflow stays a thin caller.
4. Notarize: `ditto -c -k` the staged `sovereign-macos-arm64/` folder into a zip, then `xcrun notarytool submit --wait` with an App Store Connect API key. Fail the job on anything but `Accepted`, and print the notary log.
5. Stapling is not possible for bare Mach-O files or a `.tar.gz`. Gatekeeper looks the ticket up online on first launch, which is fine for a product that already needs the network to fetch its model. If we later ship a `.pkg` or DMG, staple that.
6. Extend "Smoke-test the package" with `codesign --verify --strict --verbose=2` on every Mach-O and `spctl --assess --type execute` on `bin/sovereign`.

The `~/Applications/Sovereign.app` launcher (`install.rs:104`) is a shell script written on the user's Mac. It is never quarantined and needs no signing. Leave it as is.

## What needs Rohit's Apple credentials

Only Rohit can do these. Everything else can be done in a PR.

| Item | Where | Becomes |
| --- | --- | --- |
| Apple Developer Program membership ($99/year), individual or organization | developer.apple.com | Team ID |
| Developer ID Application certificate, exported as `.p12` with a password | Xcode or developer.apple.com > Certificates | `MACOS_CERT_P12_BASE64`, `MACOS_CERT_PASSWORD` secrets |
| The certificate's full name, for example `Developer ID Application: Rohit … (ABCDE12345)` | Keychain Access | `MACOS_SIGN_IDENTITY` secret, `SOVEREIGN_TEAM_ID` variable |
| App Store Connect API key with the Developer role: key ID, issuer ID, `.p8` file | App Store Connect > Users and Access > Integrations | `NOTARY_KEY_ID`, `NOTARY_ISSUER_ID`, `NOTARY_KEY_P8_BASE64` secrets |
| A `release` GitHub environment holding those secrets, restricted to `v*` tags, optionally with Rohit as required reviewer | Repository settings > Environments | Only tag builds can sign |

A Developer ID Installer certificate is needed only if we ship a `.pkg`. An individual account puts Rohit's legal name in the signature, which users see in Gatekeeper dialogs. An organization account needs a D-U-N-S number but shows the organization name.

Secrets never enter the repository, logs, or project memory.

## Versioning

- Semantic versioning with a single workspace version in `Cargo.toml`. Tags are `vX.Y.Z` and must equal that version (already enforced in `release.yml`).
- While below 1.0, a minor bump (`0.2.0`) is any release that changes a persisted format (`StateStore` schema, `settings-v1.json`, `projects-v1.json`) or a public CLI or API contract. Patch releases change neither.
- Tags are annotated (`git tag -a`) and cut from `main` only, after `./scripts/verify.sh` and `scripts/verify-ui.sh`.
- Release notes come from `--generate-notes`, plus a hand-written summary that names schema changes.
- Pre-releases use `vX.Y.Z-rc.N` and are marked prerelease on GitHub. `releases/latest` skips them, so `install.sh` and `sovereign update` never pick them up. Today the workflow's tag check accepts `-rc.1`, but `gh release create` does not pass `--prerelease`, so that flag must be added for tags containing `-`.
- Add a `release` job gate: the workflow should require CI to be green on the tagged commit before publishing.

## The first release: v0.1.0

The first tag should be unsigned, to prove the pipeline end to end. It does not need the Apple credentials.

1. Merge the open readiness work, and check that `main` is green in CI.
2. On a Mac, run `./scripts/verify.sh` and `scripts/verify-ui.sh`. The live-Chrome case `real_chrome_contains_page_js_writes_and_worker_network_before_execution` is a known failure that also fails on `main` (see `docs/wiki/15-testing-and-evals.md`). Decide whether it blocks a release. I recommend it does not block v0.1.0 but is listed in the notes.
3. Tag `v0.1.0-rc.1` first (after the `--prerelease` fix above), and run `install.sh` against it with `SOVEREIGN_RELEASE_BASE_URL=https://github.com/Rohitrajsaji/Sovereign/releases/download/v0.1.0-rc.1` on a clean macOS user account. Check onboarding, the model download, one goal, `sovereign update`, and `sovereign uninstall`.
4. Tag `v0.1.0` from the same commit. `install.sh` from `main` now works for anyone.
5. Signed builds start at v0.1.1 or v0.2.0, once the credentials exist and the runner check above has landed. Test that release by downloading the tarball in Safari (so it is quarantined), unpacking it, and running `bin/sovereign --version` with no Gatekeeper prompt.

## Work items, in order

1. Distribution amendment under `output/`, replacing the "out of scope" line (the frozen contract needs it before signing lands).
2. `--prerelease` for `-` tags and a CI-green gate in `release.yml`. No credentials needed.
3. First unsigned `v0.1.0-rc.1`, then `v0.1.0`. No credentials needed.
4. Bundled runner accepted by code signature (`model_setup.rs`), with tests. No credentials needed.
5. Optional signing and notarization in `package-release.sh` and `release.yml`, skipped when the secrets are absent. No credentials needed to write it; testing it needs item 6.
6. Rohit: Apple Developer membership, certificate, API key, and the `release` environment secrets.
7. First signed and notarized release, verified with a browser download on a clean Mac.
8. Later, and optional: a signed update manifest (readiness plan Phase 1, item 3), and a `.pkg` or DMG for people who do not use Terminal.
