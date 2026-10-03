package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.SchemaModel
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * API4:2023 — unbounded pagination. Finds a root field with a pagination argument
 * (first/limit/count/…) and requests a single very large page; if the server
 * accepts it without a cap/limit error, large result sets can be pulled at will.
 * One oversized value only — never looped or escalated.
 */
class PaginationAbuseCheck : GraphQLCheck {
    override val id = "pagination-abuse"
    override val owaspId = "API4:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val target = schema.queries().firstOrNull { f -> f.args.any { Heuristics.isPaginationArg(it.name) } }
            ?: return emptyList()
        val pagArg = target.args.first { Heuristics.isPaginationArg(it.name) }

        val requiredOther = target.args
            .filter { it.typeRef.isNonNull() && it.name != pagArg.name }
            .joinToString("") { "${it.name}: ${QueryBuilder.placeholderFor(schema, it.typeRef)}, " }
        val args = "$requiredOther${pagArg.name}: $LARGE"
        val doc = "query { ${target.name}($args)${QueryBuilder.selectionFor(schema, target)} }"

        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!accepted(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL pagination not capped on ${target.name} (${pagArg.name}: $LARGE accepted)",
                detail = """
                    The field `${target.name}` accepted `${pagArg.name}: $LARGE` without a page-size
                    cap or limit error. Unbounded pagination lets an attacker request enormous result
                    sets, exhausting memory/CPU/DB and amplifying any per-item work — a denial-of-service
                    and bulk-exfiltration lever.

                    One oversized value was sent; the extension does not loop or escalate.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L (5.3, Medium); higher where the list
                    returns sensitive data (bulk exposure) or each item triggers expensive resolvers.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Enforce a maximum page size server-side (clamp `${pagArg.name}` to a sane cap),
                    require pagination on list fields, and include list size in query-cost limits.
                """.trimIndent(),
                evidence = listOf(rr),
                affectedOperation = "${schema.queryType()?.name ?: "Query"}.${target.name}",
            ),
        )
    }

    companion object {
        const val LARGE = "1000000"

        fun accepted(body: String): Boolean =
            GraphQLHttp.hasData(body) && !Heuristics.containsLimitError(body)

        /** Exposed for callers that want the candidate without sending. */
        fun candidate(schema: SchemaModel) =
            schema.queries().firstOrNull { f -> f.args.any { Heuristics.isPaginationArg(it.name) } }
    }
}
