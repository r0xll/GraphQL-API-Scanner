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
2. **Run checks** — right-click a GraphQL request →
   *Send to GraphQL Analyzer & run OWASP checks*, or use the tab's **Run OWASP
   checks** button. The tab shows the introspected (or reconstructed) schema tree
   and a findings grid; each finding is added to Burp's site map as an
   `AuditIssue` with request/response evidence.
3. **Two-identity checks (BOLA/BFLA)** — supply two identities in the tab's config
   (one `Header: value` per line) and, for a firm BOLA proof, a known object id
   owned by identity A. These checks are skipped unless configured — no creds are
   ever hardcoded.

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

## Stack

Kotlin 2.1 (JDK 21), Gradle Kotlin DSL, Montoya API 2025.8, kotlinx.serialization,
JUnit5 + MockK. Package root: `com.redcell.gqlanalyzer`.
