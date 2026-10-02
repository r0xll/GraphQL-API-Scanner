package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * API3:2023 — mass assignment surface. SCHEMA-STATIC: never sends a mutation
 * (guardrail: no privileged writes). Reports input types that expose
 * client-settable privileged fields and the mutations that consume them.
 */
class MassAssignmentCheck : GraphQLCheck {
    override val id = "mass-assignment"
    override val owaspId = "API3:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val risks = Heuristics.massAssignmentSurface(schema)
        if (risks.isEmpty()) return emptyList()

        val riskyInputTypes = risks.map { it.inputType }.toSet()
        val mutations = schema.mutations().filter { m ->
            m.args.any { arg -> schema.type(arg.typeRef.namedType())?.name in riskyInputTypes }
        }.map { it.name }

        val surface = risks.joinToString("; ") { "${it.inputType}.${it.field}" }
        return listOf(
            Finding(
                name = "GraphQL mass-assignment surface (privileged input fields)",
                detail = """
                    Input types expose privileged, client-settable fields: $surface.
                    ${if (mutations.isNotEmpty()) "Reachable via mutation(s): ${mutations.joinToString(", ")}." else ""}
                    A client could set security-relevant properties (role, isAdmin, balance, status,
                    tenantId, ...) during create/update, escalating privilege or tampering with
                    ownership/financial state.

                    Detected statically from the schema; no mutation was issued (the extension never
                    writes privileged state). Validate by submitting the field with a benign value in
                    an authorized test account and confirming it is accepted/echoed.

                    CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N (8.1, High) if the field drives
                    authorization (e.g. role/isAdmin); lower where it only affects non-security state.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Use explicit input allow-lists (DTOs) that exclude privileged attributes; never
                    bind client input directly onto persistence models. Enforce server-side
                    authorization on any field that changes role, status, ownership or balance, and
                    ignore/reject unexpected input fields.
                """.trimIndent(),
            ),
        )
    }
}
