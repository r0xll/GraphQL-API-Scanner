package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * Injection insertion-point seeder (classic A03:2021 Injection; no dedicated
 * 2023 API category, filed under API8 misconfiguration). SCHEMA-STATIC: emits
 * String/ID argument insertion points and ready-to-run sqlmap/nuclei scaffolding.
 * It DOES NOT send payloads or attempt exploitation.
 */
class InjectionSeederCheck : GraphQLCheck {
    override val id = "injection-seeder"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val points = Heuristics.injectionInsertionPoints(schema)
        if (points.isEmpty()) return emptyList()

        val url = runCatching { ctx.request.url() }.getOrNull() ?: "https://TARGET/graphql"
        val listing = points.take(50).joinToString("\n") { "  - ${it.parentType}.${it.field}(${it.arg}: ${it.argType})" }
        val example = points.first()

        return listOf(
            Finding(
                name = "GraphQL injection insertion points (${points.size}) — seeding only",
                detail = """
                    String/ID arguments are candidate injection insertion points (SQLi, NoSQLi,
                    command/template injection depending on the resolver). This check only enumerates
                    them — no payloads were sent.

                    Insertion points:
                    $listing${if (points.size > 50) "\n  ... (${points.size - 50} more)" else ""}

                    sqlmap scaffold (save the request below as req.txt with the value to test marked `*`):

                      POST ${url} HTTP/1.1
                      Content-Type: application/json

                      {"query":"query{ ${example.field}(${example.arg}: \"*\"){ __typename } }"}

                      $ sqlmap -r req.txt --batch --level=5 --risk=3

                    nuclei: feed these points to a GraphQL injection template
                    (e.g. -t http/graphql/ with the arg as the fuzz position).

                    CVSS v3.1: not scored — this is tooling output, not a confirmed vulnerability.
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Use parameterized queries / prepared statements in resolvers, validate and
                    canonicalize argument values, and apply least-privilege DB accounts. Treat every
                    String/ID argument as untrusted regardless of GraphQL's type system.
                """.trimIndent(),
            ),
        )
    }
}
