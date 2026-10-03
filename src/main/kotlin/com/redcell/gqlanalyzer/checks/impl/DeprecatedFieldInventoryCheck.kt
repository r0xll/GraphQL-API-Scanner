package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.SchemaModel

/**
 * API9:2023 (Improper Inventory Management) — deprecated-field inventory.
 * SCHEMA-STATIC: lists fields the schema marks deprecated. Deprecated fields are
 * often older, less-maintained code paths with weaker authorization/validation and
 * are prime manual-review targets.
 */
class DeprecatedFieldInventoryCheck : GraphQLCheck {
    override val id = "deprecated-inventory"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val deprecated = deprecatedFields(schema)
        if (deprecated.isEmpty()) return emptyList()

        val listing = deprecated.take(60).joinToString("\n") { (type, field, reason) ->
            "  - $type.$field" + (reason?.let { " — $it" } ?: "")
        }
        return listOf(
            Finding(
                name = "Deprecated GraphQL fields present (${deprecated.size})",
                detail = """
                    The schema marks the following fields deprecated — frequently legacy code paths
                    with weaker authorization, validation or rate limiting that remain reachable:

                    $listing${if (deprecated.size > 60) "\n  ... (${deprecated.size - 60} more)" else ""}

                    Review each for authorization and input-handling parity with its replacement.

                    CVSS v3.1: not scored — inventory/hardening guidance.
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Track deprecated fields to a removal date, confirm they enforce the same
                    authorization/validation as current fields, and remove them from the production
                    schema once clients have migrated.
                """.trimIndent(),
            ),
        )
    }

    companion object {
        data class Deprecated(val type: String, val field: String, val reason: String?)

        fun deprecatedFields(schema: SchemaModel): List<Deprecated> =
            schema.types.flatMap { t ->
                t.fields.filter { it.isDeprecated }.map { Deprecated(t.name, it.name, it.deprecationReason) }
            }
    }
}
