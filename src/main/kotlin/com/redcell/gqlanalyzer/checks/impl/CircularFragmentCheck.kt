package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API4:2023 — fragment-cycle detection. The GraphQL spec requires servers to
 * reject fragment spreads that form a cycle (they would otherwise expand forever).
 * This sends ONE self-spreading fragment; if it is accepted/executed instead of
 * rejected with a cycle error, the server's validation is missing a core DoS guard.
 * Single request only — never looped or escalated.
 */
class CircularFragmentCheck : GraphQLCheck {
    override val id = "circular-fragment"
    override val owaspId = "API4:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rootType = ctx.schema?.queryTypeName ?: "Query"
        val doc = "query { ...SelfRef } fragment SelfRef on $rootType { __typename ...SelfRef }"
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!missingCycleDetection(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL fragment cycle not rejected (missing cycle detection)",
                detail = """
                    A self-spreading fragment (`fragment SelfRef on $rootType { ... ...SelfRef }`) was
                    accepted and executed instead of being rejected with a fragment-cycle validation
                    error. The spec requires servers to reject fragment cycles precisely because they
                    expand without bound; missing this check is a denial-of-service primitive.

                    One request was sent; the extension never loops or escalates this probe.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5, High) — unauthenticated
                    availability impact.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = """
                    Use a spec-compliant GraphQL execution engine with fragment-cycle validation
                    enabled (the `NoFragmentCycles` rule), and add query-cost/complexity limits as
                    defense in depth.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        /** Missing detection = resolved without a fragment-cycle rejection. */
        fun missingCycleDetection(body: String): Boolean =
            !Heuristics.containsFragmentCycleError(body) && GraphQLHttp.hasData(body)
    }
}
