package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * API7:2023 (Server-Side Request Forgery). SCHEMA-STATIC seeder: flags String/ID
 * arguments whose names suggest the resolver will dereference a URL (url, webhook,
 * callback, avatar, ...). It only enumerates candidate SSRF insertion points and
 * emits a Collaborator-ready scaffold — it never sends a payload or fetches anything.
 */
class SsrfSeederCheck : GraphQLCheck {
    override val id = "ssrf-seeder"
    override val owaspId = "API7:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val points = Heuristics.ssrfInsertionPoints(schema)
        if (points.isEmpty()) return emptyList()

        val url = runCatching { ctx.request.url() }.getOrNull() ?: "https://TARGET/graphql"
        val listing = points.take(50).joinToString("\n") { "  - ${it.parentType}.${it.field}(${it.arg}: ${it.argType})" }
        val example = points.first()

        return listOf(
            Finding(
                name = "GraphQL SSRF candidate arguments (${points.size}) — seeding only",
                detail = """
                    These String/ID arguments are named like URLs/hosts the resolver may fetch
                    server-side (SSRF candidates). This check only enumerates them — no request was
                    forged and no payload was sent.

                    Candidate insertion points:
                    $listing${if (points.size > 50) "\n  ... (${points.size - 50} more)" else ""}

                    Validate with a Burp Collaborator payload in the flagged argument, e.g.:

                      POST $url HTTP/1.1
                      Content-Type: application/json

                      {"query":"query{ ${example.field}(${example.arg}: \"http://<COLLABORATOR>/\"){ __typename } }"}

                    A DNS/HTTP hit on Collaborator confirms server-side fetch. Test internal targets
                    (169.254.169.254, 127.0.0.1, internal hostnames) per your ROE.

                    CVSS v3.1: not scored here — candidate surface, not a confirmed vulnerability.
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Validate and allow-list outbound URLs (scheme/host), resolve and pin to allowed
                    IP ranges, block link-local/loopback/metadata addresses, and disable redirects on
                    server-side fetches. Prefer an egress proxy with an explicit allow-list.
                """.trimIndent(),
            ),
        )
    }
}
