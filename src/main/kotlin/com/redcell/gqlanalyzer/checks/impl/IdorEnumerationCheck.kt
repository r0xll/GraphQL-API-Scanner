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
 * API1:2023 — IDOR / object enumeration. For an id-addressed root field, fetches two
 * adjacent ids; if both return distinct non-null objects, objects are directly
 * addressable and enumerable by id (an IDOR surface). Proof only — two ids, no
 * mass-enumeration. Confirm ownership/authz context in the deliverable.
 */
class IdorEnumerationCheck : GraphQLCheck {
    override val id = "idor-enumeration"
    override val owaspId = "API1:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val queryType = schema.queryType() ?: return emptyList()

        val field = queryType.fields.firstOrNull { f ->
            val idArg = f.args.firstOrNull { it.name.lowercase() in SchemaModel.ID_ARG_NAMES }
            idArg != null && f.args.none { it.typeRef.isNonNull() && it != idArg }
        } ?: return emptyList()
        val idArg = field.args.first { it.name.lowercase() in SchemaModel.ID_ARG_NAMES }

        val (id1, id2) = idPair(ctx.config.knownObjectId)
        val rr1 = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(QueryBuilder.singleArgQuery(schema, field, idArg.name, id1)))
        val rr2 = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(QueryBuilder.singleArgQuery(schema, field, idArg.name, id2)))
        val b1 = rr1.response()?.bodyToString().orEmpty()
        val b2 = rr2.response()?.bodyToString().orEmpty()
        if (!enumerable(b1, b2, field.name)) return emptyList()

        return listOf(
            Finding(
                name = "IDOR surface on ${field.name} (adjacent ids $id1/$id2 both resolve)",
                detail = """
                    The field `${field.name}(${idArg.name}: …)` returned distinct non-null objects for
                    two adjacent ids ($id1 and $id2). Objects are directly addressable and trivially
                    enumerable by id. If object-level authorization is not enforced per caller, this is
                    IDOR/BOLA at scale.

                    Proof used two ids only — no mass enumeration. Confirm whether the second object
                    belongs to a different principal and whether access is authorized.

                    CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium); higher if objects are
                    sensitive and ownership is not checked.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Enforce per-object authorization in the resolver (the caller must own/may access
                    the requested id) and prefer unguessable identifiers (UUIDv4) over sequential ids.
                """.trimIndent(),
                evidence = listOf(rr1, rr2),
                affectedOperation = "${schema.queryType()?.name ?: "Query"}.${field.name}",
            ),
        )
    }

    companion object {
        /** Two adjacent ids; numeric known id -> n and n+1, else "1"/"2". */
        fun idPair(knownId: String?): Pair<String, String> {
            val n = knownId?.toLongOrNull()
            return if (n != null) n.toString() to (n + 1).toString() else "1" to "2"
        }

        fun enumerable(body1: String, body2: String, field: String): Boolean {
            val a = GraphQLResponses.dataField(body1, field) ?: return false
            val b = GraphQLResponses.dataField(body2, field) ?: return false
            return a != b // both non-null (dataField returns null for JSON-null) and distinct
        }
    }
}
