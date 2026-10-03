package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.SchemaModel
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.GraphQLResponses
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * API4:2023 — depth limiting. Builds ONE deeply-nested query over a
 * self-referential field (proof depth only) and checks it is accepted. Never
 * escalates: a single query at a capped depth, no loop, no complexity bomb.
 */
class DepthComplexityCheck : GraphQLCheck {
    override val id = "depth-complexity"
    override val owaspId = "API4:2023"

    data class Cycle(val entryField: String, val cyclicField: String, val typeName: String)

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val cycle = findCycle(schema) ?: return emptyList()

        val depth = ctx.config.depthProof.coerceIn(3, MAX_DEPTH)
        val query = QueryBuilder.deepQuery(cycle.entryField, cycle.cyclicField, depth)
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!accepted(body, cycle.entryField)) return emptyList()

        return listOf(
            Finding(
                name = "No GraphQL query depth limit (accepted depth $depth)",
                detail = """
                    A query nested $depth levels deep through the self-referential field
                    `${cycle.typeName}.${cycle.cyclicField}` was accepted and resolved without a
                    depth/complexity error. Unbounded nesting lets an attacker craft exponentially
                    expensive queries, exhausting CPU/memory (denial of service).

                    Proof capped at depth $depth; the extension does NOT escalate depth or complexity.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5, High) — unauthenticated
                    availability impact.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = """
                    Enforce a maximum query depth and a query-cost/complexity budget server-side
                    (e.g. graphql-depth-limit, graphql-cost-analysis, Apollo operation limits), plus
                    pagination caps and request timeouts. Reject queries exceeding the budget before
                    execution.
                """.trimIndent(),
                evidence = listOf(rr),
                affectedOperation = "${schema.queryType()?.name ?: "Query"}.${cycle.entryField}",
            ),
        )
    }

    companion object {
        const val MAX_DEPTH = 15

        fun accepted(body: String, entryField: String): Boolean =
            GraphQLResponses.fieldNonNull(body, entryField) && !Heuristics.containsDepthLimitError(body)

        /** Find a no-required-arg root field returning object T where T has a field whose named type is also T. */
        fun findCycle(schema: SchemaModel): Cycle? {
            for (entry in schema.queries()) {
                if (entry.args.any { it.typeRef.isNonNull() }) continue
                val t = schema.type(entry.typeRef.namedType()) ?: continue
                if (t.kind != "OBJECT" && t.kind != "INTERFACE") continue
                val selfField = t.fields.firstOrNull { it.typeRef.namedType() == t.name } ?: continue
                return Cycle(entry.name, selfField.name, t.name)
            }
            return null
        }
    }
}
