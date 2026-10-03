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
 * API3:2023 — Broken Object Property Level Authorization (excessive data /
 * sensitive property exposure). Selects sensitive leaf fields under a no-arg
 * root field and reports any that are returned non-null to the caller.
 */
class FieldAuthzCheck : GraphQLCheck {
    override val id = "field-authz"
    override val owaspId = "API3:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()

        for (root in Heuristics.noArgQueryFields(schema)) {
            val rt = schema.type(root.typeRef.namedType()) ?: continue
            val sensitive = rt.fields.filter { Heuristics.isSensitiveField(it.name) }.map { it.name }
            if (sensitive.isEmpty()) continue

            val query = QueryBuilder.selectLeaves(root, sensitive)
            val rr = GraphQLHttp.postJson(
                ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query), ctx.config.authHeadersA,
            )
            val body = rr.response()?.bodyToString().orEmpty()
            val exposed = exposedFields(body, root.name, sensitive)
            if (exposed.isEmpty()) continue

            return listOf(
                Finding(
                    name = "Sensitive field exposure on ${rt.name} via ${root.name} (${exposed.joinToString(", ")})",
                    detail = """
                        The query `{ ${root.name} { ${sensitive.joinToString(" ")} } }` returned
                        non-null values for sensitive field(s): ${exposed.joinToString(", ")}.
                        Property-level authorization is missing — the caller can read fields that
                        should be restricted (credentials, tokens, PII), i.e. excessive data exposure.

                        CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium); raise to High if
                        the exposed field is a credential/secret reusable for account takeover.
                    """.trimIndent(),
                    severity = Severity.HIGH,
                    confidence = Confidence.FIRM,
                    remediation = """
                        Apply field-level authorization: resolve sensitive fields only for principals
                        permitted to see them (null them out otherwise), or remove them from the API
                        surface entirely. Never return password hashes, tokens or secrets through the
                        graph. Consider field-level `@auth` directives and schema review.
                    """.trimIndent(),
                    evidence = listOf(rr),
                    affectedOperation = "${schema.queryType()?.name ?: "Query"}.${root.name}",
                ),
            )
        }
        return emptyList()
    }

    companion object {
        /** Which of [sensitive] came back non-null under data.<root>. */
        fun exposedFields(body: String, root: String, sensitive: List<String>): List<String> {
            val rootEl = GraphQLResponses.dataField(body, root) as? kotlinx.serialization.json.JsonObject
                ?: return emptyList()
            return sensitive.filter { f ->
                val v = rootEl[f]
                v != null && v !is kotlinx.serialization.json.JsonNull
            }
        }
    }
}
