package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.IntrospectionParser
import com.redcell.gqlanalyzer.schema.Introspection
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API9:2023 (Improper Inventory Management) — introspection enabled in prod.
 * Sends one standard `__schema` query and reports if the full type system is returned.
 */
class IntrospectionCheck : GraphQLCheck {
    override val id = "introspection"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(Introspection.QUERY))
        val body = rr.response()?.bodyToString().orEmpty()
        if (!introspectionEnabled(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL introspection enabled",
                detail = """
                    The endpoint answered a full `__schema` introspection query and returned the
                    complete type system — every type, field, argument and deprecation. In a
                    production deployment this hands an attacker the entire API attack surface for
                    free, removing the reconnaissance barrier for authorization, injection and
                    mass-assignment testing.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — network-reachable
                    confidentiality-only disclosure of the schema, no auth required.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Disable introspection in production. Apollo Server: `introspection: false`.
                    graphql-java / graphql-js: install the `NoSchemaIntrospection` validation rule.
                    Where introspection is required for internal tooling, gate it behind
                    authentication and network ACLs rather than leaving it world-readable.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        /** Pure: does this response body contain a populated `__schema`? */
        fun introspectionEnabled(body: String): Boolean =
            IntrospectionParser.parse(body)?.types?.isNotEmpty() == true
    }
}
