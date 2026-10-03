package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.GraphQLResponses
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * API5:2023 — Broken Function Level Authorization. Invokes a privileged-looking
 * QUERY (never a mutation — guardrail: no privileged writes) as the low-privilege
 * identity A. Fires if it is authorized (data returned, no authz error). Requires
 * identity A to be configured.
 */
class BflaCheck : GraphQLCheck {
    override val id = "bfla"
    override val owaspId = "API5:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        if (ctx.config.authHeadersA.isEmpty()) return emptyList()
        val schema = ctx.schema ?: return emptyList()
        // Only no-required-arg privileged QUERY fields — safe, read-only, non-persisting.
        val target = Heuristics.privilegedQueryFields(schema)
            .firstOrNull { f -> f.args.none { it.typeRef.isNonNull() } } ?: return emptyList()

        val query = QueryBuilder.bareFieldQuery(schema, target)
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query), ctx.config.authHeadersA)
        val body = rr.response()?.bodyToString().orEmpty()
        if (!authorized(body, target.name)) return emptyList()

        return listOf(
            Finding(
                name = "Potential BFLA: privileged field '${target.name}' accessible to low-privilege identity",
                detail = """
                    The privileged query field `${target.name}` returned data for identity A
                    (configured as the low-privilege principal) with no authorization error. A
                    standard user reaching an administrative/privileged function is Broken Function
                    Level Authorization.

                    Read-only proof only; no mutation was invoked. Confirm that identity A is genuinely
                    unprivileged for this operation in the deliverable.

                    CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium); add I:H (→ 8.1 High)
                    if the privileged function also mutates state.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = """
                    Enforce function-level authorization server-side on every privileged
                    query/mutation (deny-by-default, role/permission checks in the resolver or a
                    schema directive like `@auth(requires: ADMIN)`). Do not rely on the field being
                    hidden from the UI or absent from introspection.
                """.trimIndent(),
                evidence = listOf(rr),
                affectedOperation = "${schema.queryType()?.name ?: "Query"}.${target.name}",
            ),
        )
    }

    companion object {
        /** Authorized = field returned non-null data and no authz-denial error present. */
        fun authorized(body: String, field: String): Boolean =
            GraphQLResponses.fieldNonNull(body, field) && !Heuristics.containsAuthzError(body)
    }
}
