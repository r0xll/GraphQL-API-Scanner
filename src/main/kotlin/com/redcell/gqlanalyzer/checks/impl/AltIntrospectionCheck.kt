package com.redcell.gqlanalyzer.checks.impl

import burp.api.montoya.http.message.HttpRequestResponse
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.Introspection
import com.redcell.gqlanalyzer.schema.IntrospectionParser
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject

/**
 * API9:2023 — alternate introspection paths. Fires only when the standard POST
 * `__schema` is blocked but the schema still leaks via GET, `text/plain`, or a
 * `__type(...)` probe — i.e. a blocklist that misses an access path.
 */
class AltIntrospectionCheck : GraphQLCheck {
    override val id = "alt-introspection"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        // If standard POST introspection already works, IntrospectionCheck owns it.
        val postRR = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(Introspection.QUERY))
        if (schemaLeaks(postRR.response()?.bodyToString().orEmpty())) return emptyList()

        val vectors = mutableListOf<String>()
        val evidence = mutableListOf<HttpRequestResponse>()

        val getRR = GraphQLHttp.getWithQuery(ctx.api, ctx.request, Introspection.QUERY)
        if (schemaLeaks(getRR.response()?.bodyToString().orEmpty())) {
            vectors += "HTTP GET `?query=`"; evidence += getRR
        }
        val textRR = GraphQLHttp.postText(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(Introspection.QUERY))
        if (schemaLeaks(textRR.response()?.bodyToString().orEmpty())) {
            vectors += "POST `text/plain`"; evidence += textRR
        }
        val typeRR = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(TYPE_PROBE))
        if (typeProbeLeaks(typeRR.response()?.bodyToString().orEmpty())) {
            vectors += "`__type(...)` field probe"; evidence += typeRR
        }
        if (vectors.isEmpty()) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL introspection reachable via alternate path (${vectors.joinToString(", ")})",
                detail = """
                    Standard POST `__schema` introspection is blocked, but the schema is still
                    recoverable through: ${vectors.joinToString(", ")}. The introspection control is
                    incomplete — it filters one access path while leaving others open, so an attacker
                    reconstructs the full type system anyway.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — schema disclosure
                    without authentication.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Disable introspection at the schema/validation layer (e.g. a
                    `NoSchemaIntrospection` validation rule) so it is blocked for every transport and
                    for `__type`/`__schema` alike — not via a per-method or per-content-type filter.
                """.trimIndent(),
                evidence = evidence,
            ),
        )
    }

    companion object {
        val TYPE_PROBE = "query { __type(name: \"Query\") { name fields { name } } }"

        fun schemaLeaks(body: String): Boolean =
            IntrospectionParser.parse(body)?.types?.isNotEmpty() == true

        /** data.__type.fields is a non-empty array. */
        fun typeProbeLeaks(body: String): Boolean {
            val root = runCatching { GraphQLHttp.json.parseToJsonElement(body) }.getOrNull() as? JsonObject
                ?: return false
            val data = root["data"] as? JsonObject ?: return false
            val type = data["__type"] as? JsonObject ?: return false
            val fields = type["fields"] as? JsonArray ?: return false
            return fields.isNotEmpty()
        }
    }
}
