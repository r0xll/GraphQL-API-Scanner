package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API9/API4 — incremental delivery (`@defer`/`@stream`) support. Sends a query
 * using `@defer`; if accepted (no "unknown directive" validation error) the server
 * supports incremental delivery, which is both an inventory fact and a DoS lever
 * (many deferred fragments inflate work / hold connections).
 */
class DeferStreamCheck : GraphQLCheck {
    override val id = "defer-stream"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(PROBE))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!deferSupported(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL incremental delivery (@defer/@stream) supported",
                detail = """
                    A query using `@defer` was accepted without an unknown-directive error, so the
                    server supports incremental delivery. Beyond inventory, `@defer`/`@stream` are a
                    denial-of-service lever: a query with many deferred fragments can inflate work and
                    hold the response open. Pair with query-cost limiting review.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3, Medium) — availability
                    consideration; informational on its own.
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.FIRM,
                remediation = """
                    If incremental delivery is not required, disable `@defer`/`@stream`. If it is,
                    include deferred fragments in query-cost/complexity limits and cap the number of
                    incremental payloads per operation.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        val PROBE = "query { __typename ... @defer { __typename } }"

        /** Supported = resolved (or an incremental-delivery payload) with no @defer validation error. */
        fun deferSupported(body: String): Boolean {
            val deferRejected = GraphQLHttp.errorMessages(body).any {
                it.contains("defer", ignoreCase = true) &&
                    (it.contains("unknown", ignoreCase = true) || it.contains("not supported", ignoreCase = true) ||
                        it.contains("cannot", ignoreCase = true) || it.contains("disabled", ignoreCase = true))
            }
            if (deferRejected) return false
            val incremental = body.contains("hasNext", ignoreCase = true) || body.contains("\"incremental\"", ignoreCase = true)
            return GraphQLHttp.hasData(body) || incremental
        }
    }
}
