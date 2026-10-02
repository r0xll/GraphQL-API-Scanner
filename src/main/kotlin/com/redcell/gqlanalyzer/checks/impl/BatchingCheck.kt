package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.AliasBatch
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.GraphQLResponses

/**
 * API4:2023 (Unrestricted Resource Consumption) — query batching.
 * Probes two batching styles, each PROOF-LEVEL capped at 10 (never looped larger):
 *   1. alias batching — one query with N aliased benign fields,
 *   2. JSON-array batching — an array of N benign envelopes.
 * A vector only fires if ALL aliases/ops resolved in the single response.
 */
class BatchingCheck : GraphQLCheck {
    override val id = "batching"
    override val owaspId = "API4:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        // Hard proof-level cap: never exceed 10 regardless of config.
        val n = minOf(ctx.config.maxBatch, PROOF_CAP).coerceAtLeast(2)

        val (aliasQuery, aliases) = AliasBatch.aliasQuery(n)
        val aliasRR = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(aliasQuery))
        val aliasHit = GraphQLResponses.aliasesResolved(aliasRR.response()?.bodyToString().orEmpty(), aliases)

        val arrRR = GraphQLHttp.postJson(
            ctx.api, ctx.request, GraphQLHttp.batchEnvelope(List(n) { "{__typename}" }),
        )
        val arrHit = GraphQLResponses.arrayBatchResolved(arrRR.response()?.bodyToString().orEmpty(), n)

        if (!aliasHit && !arrHit) return emptyList()

        val vectors = buildList {
            if (aliasHit) add("alias batching ($n aliases in one query)")
            if (arrHit) add("JSON-array batching ($n operations in one request)")
        }
        val evidence = buildList {
            if (aliasHit) add(aliasRR)
            if (arrHit) add(arrRR)
        }

        return listOf(
            Finding(
                name = "GraphQL query batching allowed (${vectors.size} vector(s))",
                detail = """
                    The endpoint resolved all operations in a single batched request via
                    ${vectors.joinToString(" and ")}. Batching multiplies the work (and the number of
                    sensitive operations) per HTTP request, which lets an attacker amplify
                    resource consumption and, critically, bypass per-request rate limiting and
                    anti-automation on authentication-adjacent fields — e.g. hundreds of
                    `login`/`verifyOtp`/`resetPassword` attempts smuggled inside one request that
                    counts as a single hit against a WAF or rate limiter.

                    Proof was capped at $n operations; the extension never loops to a larger batch.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3, Medium) baseline for the
                    availability amplification; raise to High if batching fronts an authentication
                    mutation (credential-stuffing / OTP brute-force at N× per request).
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Enforce a server-side batch limit (ideally disable array batching unless needed)
                    and count every operation in a batch toward rate limits and cost analysis.
                    Reject alias abuse with a per-operation alias cap and query-cost limiting
                    (e.g. graphql-cost-analysis, Apollo operation limits). Apply rate limiting and
                    anti-automation to sensitive mutations at the operation level, not the HTTP level.
                """.trimIndent(),
                evidence = evidence,
            ),
        )
    }

    companion object {
        const val PROOF_CAP = 10
    }
}
