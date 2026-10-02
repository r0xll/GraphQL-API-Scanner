package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.SchemaReconstructor
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API9:2023 — field-suggestion leakage ("Did you mean ..."). Even with
 * introspection disabled, validation suggestions let an attacker reconstruct
 * the schema. One bogus-field probe; fires if any suggestion leaks.
 */
class FieldSuggestionCheck : GraphQLCheck {
    override val id = "field-suggestions"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(PROBE))
        val body = rr.response()?.bodyToString().orEmpty()
        val recon = SchemaReconstructor.reconstruct(GraphQLHttp.errorMessages(body))
        if (recon.isEmpty) return emptyList()

        val leaked = recon.allSuggestions.take(20).joinToString(", ")
        return listOf(
            Finding(
                name = "GraphQL field-suggestion leakage ('Did you mean')",
                detail = """
                    A query for a non-existent field returned validation suggestions, leaking valid
                    field/type names: $leaked${if (recon.allSuggestions.size > 20) ", ..." else ""}.
                    This defeats the point of disabling introspection — an attacker can reconstruct
                    the schema field-by-field (clairvoyance), recovering the attack surface for
                    authorization and injection testing.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — schema disclosure
                    without authentication.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Disable field suggestions in production (graphql-js: run with
                    `validationRules` that strip `didYouMean`, or set production mode so suggestions
                    are suppressed; Apollo: disable in production). Combine with disabled
                    introspection and generic validation error messages.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        const val PROBE = "{ zzqInvalidField_x1 }"
    }
}
