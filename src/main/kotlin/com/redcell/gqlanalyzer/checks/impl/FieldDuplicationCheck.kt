package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API4:2023 — field duplication (graphql-cop parity). Sends the same field repeated
 * N times (proof-capped at 10). A spec-compliant server collapses identical
 * selections, but engines that re-resolve each occurrence do N× the work; acceptance
 * without a cost/duplication limit is a (weak) amplification signal.
 */
class FieldDuplicationCheck : GraphQLCheck {
    override val id = "field-duplication"
    override val owaspId = "API4:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val n = PROOF_CAP
        val doc = "{ " + (0 until n).joinToString(" ") { "__typename" } + " }"
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!GraphQLHttp.hasData(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL field duplication accepted ($n repeats)",
                detail = """
                    A query repeating the same field $n times was accepted and resolved. Combined with
                    aliasing and depth, duplicated selections multiply execution cost; the absence of a
                    duplication/cost limit is a denial-of-service amplification lever. (Alias-based
                    batching amplification is reported separately by the batching check.)

                    Proof capped at $n repeats; never escalated.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3, Medium) in aggregate with
                    other unbounded-cost vectors.
                """.trimIndent(),
                severity = Severity.LOW,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Add query-cost/complexity analysis that counts duplicated selections, and cap
                    total query cost before execution (graphql-cost-analysis, Apollo operation limits).
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        const val PROOF_CAP = 10
    }
}
