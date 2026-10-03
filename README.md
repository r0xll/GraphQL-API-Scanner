# GraphQL OWASP-API Analyzer

A Burp Suite extension (Montoya API, Kotlin) that detects GraphQL endpoints and
runs OWASP API Security Top 10 (2023) checks, surfacing results as native Burp
`AuditIssue`s and in a custom **GraphQL OWASP-API Analyzer** tab.

> Proof-level only. No check sends more than 10 batched/aliased operations,
> recurses depth as an attack, or writes privileged state. Mutation-adjacent
> risks (mass assignment, BFLA) are detected via schema analysis / response
> shape — never by confirming persistence.

## Build

```fish
./gradlew build        # compile + test (must stay green)
./gradlew shadowJar    # produce the loadable fat JAR
```

Artifact: `build/libs/graphql-owasp-analyzer-0.1.0-all.jar`
(Montoya API is `compileOnly` — provided by Burp, never bundled.)

## Load

Burp → **Extensions → Add** → Extension type *Java* → select the `-all.jar`.
On load the Output tab logs:
`GraphQL OWASP-API Analyzer v0.1.0 loaded. Passive detection, UI tab, and scan check active.`

## Use

1. **Passive detection** — proxy traffic through Burp; GraphQL responses are
   highlighted (cyan) and annotated, and a passive scan issue is raised per
   endpoint. Fingerprints on path (`/(graphql|graphiql|playground|altair)`),
   request body (top-level `query`/`mutation`/`operationName`), or `data`+`errors`
   response shape.
2. **Open a target tab** — right-click a GraphQL request → *Send to GraphQL
   Analyzer*. Each request you send becomes its own **closable, Repeater-style
   tab**, so multiple targets are retained side by side (not overwritten).
3. **Enumerate** — in the target tab, click **Enumerate**: the extension confirms
   introspection, fetches (or reconstructs) the schema into the tree, runs the
   endpoint-level OWASP checks, and lists every root operation in the
   **Operations** grid. If introspection is disabled, click **Load schema (OOB)…**
   instead and pick a client-provided schema file — an introspection JSON dump
   (`schema.json`, in the `{"data":{"__schema":…}}`, `{"__schema":…}`, or bare-schema
   shapes) or GraphQL **SDL** (`.graphql`/`.graphqls`). The schema populates the tree
   and operations grid and drives the schema-static checks + per-operation scan
   exactly as live introspection would — no introspection request is sent.
   The scanner is **adaptive about input**: required arguments get format-aware sample
   values for common custom scalars (DateTime/UUID/Email/URL/…), and when the server
   rejects a value with a scalar-validation error it feeds that error back in to
   synthesize a satisfying value and retries (bounded). An operation whose input still
   can't be satisfied is marked **INVALID_INPUT** rather than ERROR.
4. **Crawl & scan per operation** — the Operations grid is Burp-API-scan-style:
   **all operations are ticked by default**; untick the ones you don't want, or click
   the **Test** column header to toggle all on/off, then click **Scan selected**. (The
   explicit Scan — not enumerate — is the write-safety gate for mutations.) Each
   selected operation is probed individually; its status (RESOLVED / DENIED / EMPTY /
   ERROR) and per-operation findings appear in the grid, and every finding is added to
   Burp's site map as an `AuditIssue` with evidence. Per-operation findings cover BOLA
   (API1), BFLA (API5), sensitive-field exposure (API3), and verbose errors (API8),
   tagged `url#QUERY.fieldName`.
5. **Edit & re-test an operation** — double-click any row in the Operations grid (handy for
   ones stuck at **INVALID_INPUT**/**ERROR**) to open a Repeater-style editor: it shows the exact
   request the scanner sent and the API's response. Edit the request — query, variables, or
   headers — click **Send** to re-run just that operation, read the new response, and **Apply to
   grid** to push the re-scored status and any findings back. The request is sent only when you
   click Send (the write gate), so a mutation goes out only on your explicit action.
6. **Two-identity checks (BOLA/BFLA)** — in each target's **Config** sub-tab, supply
   two identities (one `Header: value` per line) and, for a firm BOLA proof, a known
   object id owned by identity A. These checks are skipped unless configured — no creds
   are ever hardcoded.

## Checks

| Check | OWASP | Method |
|---|---|---|
| Introspection enabled | API9:2023 | `__schema` probe |
| Field-suggestion leakage | API9:2023 | "Did you mean" clairvoyance |
| CSRF (GET / form-urlencoded) | API8:2023 | benign `{__typename}` over forgeable transports |
| Query batching (alias + array) | API4:2023 | capped at 10, fires only if all resolve |
| Depth limiting | API4:2023 | one self-referential deep query (cap 15), no escalation |
| Sensitive field exposure | API3:2023 | sensitive leaf fields returned to caller |
| Mass-assignment surface | API3:2023 | schema-static (sends nothing) |
| BOLA | API1:2023 | two-identity object access |
| BFLA | API5:2023 | privileged query reachable by low-priv identity (read-only) |
| Verbose errors | API8:2023 | stack-trace / SQL / framework leakage |
| Injection insertion points | (A03 Injection) | schema-static seeder for sqlmap/nuclei |
| Active in-band injection | API8:2023 / A03 | query-root String/ID args: `'` → backend SQL/NoSQL error (baseline-subtracted), `${7*7}` → evaluated to `49` (SSTI) |
| SSRF candidate arguments | API7:2023 | schema-static seeder (url/webhook/callback args) + Collaborator scaffold |
| GraphQL IDE exposed in prod | API8:2023 | GET detects GraphiQL/Playground/Altair |
| Content-Type CORS bypass | API8:2023 | `{__typename}` as `text/plain` (simple request, no preflight) |
| Directive overloading | API4:2023 | 10 repeated `@skip` directives accepted (proof-capped) |
| Engine fingerprinting | API9:2023 | graphw00f-style engine ID from error signatures |
| Alternate introspection | API9:2023 | schema leaks via GET / text-plain / `__type` when POST blocked |
| APQ enabled | API9:2023 | Automatic Persisted Queries detected (`PersistedQueryNotFound`) |
| Tracing/perf extensions | API8:2023 | `extensions.tracing`/`apollo` leaked to clients |
| Incremental delivery | API9:2023 | `@defer`/`@stream` supported (recon + DoS lever) |
| Deprecated-field inventory | API9:2023 | schema-static list of deprecated fields |
| Fragment-cycle detection | API4:2023 | self-spreading fragment accepted (missing cycle guard) |
| Unbounded pagination | API4:2023 | `first/limit:1000000` accepted with no cap |
| Field duplication | API4:2023 | field repeated ×10 accepted (proof-capped) |
| Confirmed SSRF (OOB) | API7:2023 | Collaborator URL in a URL-arg fires out-of-band |
| OOB canary injection | API7:2023 | Collaborator URL in any string arg fires out-of-band |
| IDOR / object enumeration | API1:2023 | adjacent ids both resolve to distinct objects |
| Auth brute-force amplification | API2:2023 | schema-static: batchable auth operations (rate-limit bypass) |
| CORS misconfiguration | API8:2023 | reflected Origin + credentials (credentialed cross-origin read) |
| BFLA (per-operation, incl. mutations) | API5:2023 | privileged op resolves for the low-priv identity (operation scan) |
| Sensitive business flows | API6:2023 | schema-static: high-value mutations flagged for manual review |
| User enumeration | API2:2023 | config-gated: valid vs invalid identifier login differential |
| CSWSH (subscriptions) | API8:2023 | cross-origin WebSocket handshake accepted |

## Active out-of-band checks (Burp Collaborator)

The SSRF/OOB checks (`active-ssrf`, `oob-canary-injection`) confirm findings via Burp
Collaborator: they inject a unique Collaborator URL into read-only root-query string
arguments and report only those that produce a real out-of-band interaction. They
**no-op unless Collaborator is available**, target query-root fields only (never fire a
mutation), use canary URLs only (non-destructive), and poll briefly for interactions —
so an Enumerate run with Collaborator enabled takes a little longer. This confirmation
step is the extension's key differentiator over static GraphQL scanners.

## Active in-band injection (no Collaborator)

`active-injection` complements the static seeder and the OOB canary with a lightweight,
non-destructive in-band probe. For each String/ID argument on a **read-only root query
field** (capped, never a mutation/subscription) it sends a clean baseline request, then a
single quote and `${7*7}`, and compares against the baseline: a *new* backend error
signature (SQLSTATE / SQL syntax / Oracle / Mongo …) ⇒ error-based SQL/NoSQL injection
(FIRM), and `${7*7}` coming back as `49` ⇒ template/expression injection (SSTI, TENTATIVE —
confirm it's evaluation, not coincidence). Payloads are benign (a quote and an arithmetic
expression); there is no boolean-blind data tampering, stacked/destructive SQL, or OS command
execution. Use the injection-seeder's sqlmap scaffold to confirm and exploit a hit.

## Stack

Kotlin 2.1 (JDK 21), Gradle Kotlin DSL, Montoya API 2025.8, kotlinx.serialization,
JUnit5 + MockK. Package root: `com.redcell.gqlanalyzer`.
