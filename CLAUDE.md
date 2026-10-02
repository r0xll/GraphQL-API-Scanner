# Project working agreements

## Release policy (standing rule)

**Always cut a new GitHub release for every feature or bug fix.** After the change
is committed, pushed, and the build is green:

1. Bump the version:
   - `const val VERSION` in `src/main/kotlin/com/redcell/gqlanalyzer/GraphQLAnalyzer.kt`
   - the default `version` in `build.gradle.kts`
   - Semver: **feature → minor** (0.x.0), **bug fix → patch** (0.0.x), breaking → major.
2. Release via the **Release** workflow (`.github/workflows/release.yml`), which
   builds the fat JAR (version from the tag) and publishes it as a GitHub Release.
   - Preferred when a tag can be pushed: `git tag vX.Y.Z && git push origin vX.Y.Z`.
   - In cloud sessions the branch credential often **cannot push tags (403)** — then
     trigger the workflow via `workflow_dispatch` with input `tag=vX.Y.Z`; the
     `softprops/action-gh-release` step creates the tag at the built commit.
3. Confirm the release exists and the `*-all.jar` asset is attached before reporting done.

## Build / verify

- `./gradlew build` — compile + test (must stay green before any release).
- `./gradlew shadowJar` — loadable fat JAR at `build/libs/*-all.jar`.
- Montoya API is `compileOnly` (Burp provides it at runtime) — never bundle it.

## Guardrails (hard rules — do not relax)

- Proof-level only: no check sends > 10 batched/aliased ops, recurses depth as an
  attack, or writes privileged state.
- Mutations/subscriptions are executed only via the explicit **Scan selected** action
  after the operator reviews the Operations grid. Operations default to selected, so
  the write-safety gate is the operator deselecting what they don't want (and the
  deliberate Scan click) — never an automatic scan on enumerate.
- Two-auth checks (BOLA/BFLA) take credentials from config — never hardcoded.
- Every check/analyzer is unit-tested against a fixture.
