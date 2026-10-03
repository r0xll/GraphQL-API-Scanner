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
   **Operations** grid.
4. **Crawl & scan per operation** — the Operations grid is Burp-API-scan-style:
   **all operations are ticked by default**; untick the ones you don't want, or click
   the **Test** column header to toggle all on/off, then click **Scan selected**. (The
   explicit Scan — not enumerate — is the write-safety gate for mutations.) Each
   selected operation is probed individually; its status (RESOLVED / DENIED / EMPTY /
   ERROR) and per-operation findings appear in the grid, and every finding is added to
   Burp's site map as an `AuditIssue` with evidence. Per-operation findings cover BOLA
   (API1), BFLA (API5), sensitive-field exposure (API3), and verbose errors (API8),
   tagged `url#QUERY.fieldName`.
5. **Two-identity checks (BOLA/BFLA)** — in each target's **Config** sub-tab, supply
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

## Stack

Kotlin 2.1 (JDK 21), Gradle Kotlin DSL, Montoya API 2025.8, kotlinx.serialization,
JUnit5 + MockK. Package root: `com.redcell.gqlanalyzer`.
