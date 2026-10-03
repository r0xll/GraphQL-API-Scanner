package com.redcell.gqlanalyzer.checks.impl

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
 * API1:2023 — Broken Object Level Authorization. Two-auth-context: requests an
 * id-addressed object as identity A and identity B. Proof-level (one id). Creds
 * come from config; the check is skipped unless two identities are supplied.
 */
class BolaCheck : GraphQLCheck {
    override val id = "bola"
    override val owaspId = "API1:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        if (!ctx.config.hasTwoIdentities) return emptyList()
        val schema = ctx.schema ?: return emptyList()
        val (type, field) = schema.idBearingFields().firstOrNull() ?: return emptyList()
        val idArg = field.args.first { it.name.lowercase() in SchemaModel.ID_ARG_NAMES }

        val knownId = ctx.config.knownObjectId
        val id = knownId ?: "1"
        val query = QueryBuilder.singleArgQuery(schema, field, idArg.name, id)

        val aRR = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query), ctx.config.authHeadersA)
        val bRR = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(query), ctx.config.authHeadersB)
        val aBody = aRR.response()?.bodyToString().orEmpty()
        val bBody = bRR.response()?.bodyToString().orEmpty()

        val verdict = decide(aBody, bBody, field.name, knownId != null) ?: return emptyList()

        return listOf(
            Finding(
                name = "Potential BOLA on ${type.name}.${field.name} (cross-identity object access)",
                detail = """
                    ${verdict.detail}
                    Target: `${field.name}(${idArg.name}: ${QueryBuilder.literal(id)})` on type `${type.name}`.
                    Proof used a single object id (no enumeration). Confirm ownership in the client
                    deliverable: object id must demonstrably belong to identity A while identity B is
                    a separate, unauthorized principal.

                    CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium); raise to High/Critical
                    (add I:H) if the same pattern permits modification, or if objects are trivially
                    enumerable (IDOR at scale).
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = verdict.confidence,
                remediation = """
                    Enforce object-level authorization in every resolver that accepts an object id:
                    check that the authenticated principal owns or may access the requested object,
                    server-side, before returning it. Prefer unguessable ids (UUIDv4) and deny-by-default.
                """.trimIndent(),
                evidence = listOf(aRR, bRR),
                affectedOperation = "${type.name}.${field.name}",
            ),
        )
    }

    data class Verdict(val detail: String, val confidence: Confidence)

    companion object {
        /**
         * @param knownOwnership true when the id provably belongs to identity A.
         */
        fun decide(aBody: String, bBody: String, field: String, knownOwnership: Boolean): Verdict? {
            val bHas = GraphQLResponses.fieldNonNull(bBody, field)
            if (knownOwnership) {
                // The object belongs to A; if B can read it, that is BOLA.
                return if (bHas) {
                    Verdict(
                        "Identity B successfully read an object owned by identity A.",
                        Confidence.FIRM,
                    )
                } else {
                    null
                }
            }
            // No ownership knowledge: suspicious only if both identities get the same non-null object.
            return if (GraphQLResponses.fieldEqualNonNull(aBody, bBody, field)) {
                Verdict(
                    "Both identities received the identical non-null object for the same id, " +
                        "suggesting object access is not scoped to the caller.",
                    Confidence.TENTATIVE,
                )
            } else {
                null
            }
        }
    }
}
