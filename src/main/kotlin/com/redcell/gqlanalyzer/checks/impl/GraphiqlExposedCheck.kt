package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 (Security Misconfiguration) / API9 (Improper Inventory). GETs the
 * endpoint path and detects an in-browser GraphQL IDE (GraphiQL, Playground, Altair)
 * served in production — a recon surface that should not be publicly exposed.
 */
class GraphiqlExposedCheck : GraphQLCheck {
    override val id = "graphiql-exposed"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.getPath(ctx.api, ctx.request)
        val resp = rr.response() ?: return emptyList()
        if (resp.statusCode().toInt() !in 200..299) return emptyList()
        if (!Heuristics.isGraphqlIdeHtml(resp.bodyToString())) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL IDE exposed in production (GraphiQL/Playground/Altair)",
                detail = """
                    A GET to the endpoint returned an in-browser GraphQL IDE. Shipping GraphiQL,
                    GraphQL Playground or Altair in production hands an attacker an interactive,
                    schema-aware console for crafting queries and lowers the barrier to every other
                    issue here.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — exposure of a
                    development/recon surface to unauthenticated users.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Disable the GraphQL IDE in production (Apollo: `ApolloServerPluginLandingPageDisabled`
                    / do not install the local landing page; graphql-ruby / others: disable GraphiQL in
                    prod). If needed internally, gate it behind authentication and network ACLs.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }
}
