package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API4:2023 (Unrestricted Resource Consumption) — directive overloading. The GraphQL
 * spec forbids repeating a non-repeatable directive on one location; servers that
 * accept it (and process it) lack the validation that also caps query cost, so a
 * query can be inflated with directives. PROOF-CAPPED at 10 repeats — never escalated.
 *
 * The field-duplication half of this DoS family is already covered by
 * [BatchingCheck] (alias batching); this adds the directive-overload signal.
 */
class DirectiveOverloadCheck : GraphQLCheck {
    override val id = "directive-overload"
    override val owaspId = "API4:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val n = PROOF_CAP
        val directives = (0 until n).joinToString(" ") { "@skip(if: false)" }
        val query = "{ __typename $directives }"
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!accepted(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL directive overloading accepted ($n repeated directives)",
                detail = """
                    A query carrying $n repeated `@skip` directives on a single field was accepted and
                    resolved without a duplicate-directive validation error. The GraphQL spec forbids
                    repeating a non-repeatable directive, so acceptance indicates validation is relaxed
                    and no query-cost limiting is in place — an attacker can inflate parsing/validation
                    work with directives (and combine it with depth/aliases) for denial of service.

                    Proof was capped at $n directives; the extension never escalates.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3, Medium) — availability
                    amplification; higher in aggregate with other unbounded-cost vectors.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Enforce GraphQL validation strictly (reject duplicate non-repeatable directives)
                    and add query-cost/complexity limiting and a directive-count cap before execution
                    (e.g. graphql-cost-analysis, Apollo operation limits).
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        const val PROOF_CAP = 10

        /** Accepted = resolved data with no validation/authz error. */
        fun accepted(body: String): Boolean =
            GraphQLHttp.hasData(body) &&
                !Heuristics.containsAuthzError(body) &&
                GraphQLHttp.errorMessages(body).isEmpty()
    }
}
