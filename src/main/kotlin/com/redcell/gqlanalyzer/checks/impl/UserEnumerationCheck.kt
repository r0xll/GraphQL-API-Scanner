package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * API2:2023 — username/account enumeration. CONFIG-GATED: runs only when the operator
 * supplies a known-valid and known-invalid identifier (that config is the opt-in to the
 * two probes). Sends the same auth operation twice (dummy password → failed logins,
 * non-destructive) and reports a response differential that lets an attacker tell which
 * identifiers exist.
 */
class UserEnumerationCheck : GraphQLCheck {
    override val id = "user-enumeration"
    override val owaspId = "API2:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val cfg = ctx.config
        if (!cfg.hasUserEnumConfig) return emptyList()
        val schema = ctx.schema ?: return emptyList()

        val field = (schema.queries() + schema.mutations()).firstOrNull { f ->
            Heuristics.isAuthField(f.name) && f.args.any { Heuristics.isIdentifierArg(it.name) }
        } ?: return emptyList()
        val idArg = field.args.first { Heuristics.isIdentifierArg(it.name) }

        val validId = cfg.userEnumValid!!
        val invalidId = cfg.userEnumInvalid!!
        val rrValid = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(QueryBuilder.injectedQuery(schema, field, idArg.name, validId)))
        val rrInvalid = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(QueryBuilder.injectedQuery(schema, field, idArg.name, invalidId)))
        val bValid = rrValid.response()?.bodyToString().orEmpty()
        val bInvalid = rrInvalid.response()?.bodyToString().orEmpty()
        if (!reveals(bValid, bInvalid, validId, invalidId)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL user enumeration via ${field.name} (distinct responses for valid vs invalid identifier)",
                detail = """
                    The auth operation `${field.name}` responded differently for a known-valid
                    identifier than for a known-invalid one (same dummy password), so an attacker can
                    determine which accounts exist — enabling targeted credential stuffing, password
                    spraying and phishing.

                    Probes used failed logins only; no account was accessed.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — unauthenticated
                    disclosure of account existence.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Return a single generic message for all authentication failures (never
                    distinguish "no such user" from "wrong password"), keep response timing uniform,
                    and apply the same rate limiting to valid and invalid identifiers.
                """.trimIndent(),
                evidence = listOf(rrValid, rrInvalid),
            ),
        )
    }

    companion object {
        /** True when the two responses differ in error templates (identifiers stripped) or data presence. */
        fun reveals(validBody: String, invalidBody: String, validId: String, invalidId: String): Boolean {
            val tValid = templates(GraphQLHttp.errorMessages(validBody), validId, invalidId)
            val tInvalid = templates(GraphQLHttp.errorMessages(invalidBody), validId, invalidId)
            if (tValid != tInvalid) return true
            return GraphQLHttp.hasData(validBody) != GraphQLHttp.hasData(invalidBody)
        }

        /** Normalize messages: drop the identifiers, collapse digits, lowercase — compare the templates. */
        private fun templates(messages: List<String>, vararg ids: String): Set<String> =
            messages.map { msg ->
                var m = msg.lowercase()
                ids.forEach { m = m.replace(it.lowercase(), "") }
                m.replace(Regex("\\d+"), "#").replace(Regex("\\s+"), " ").trim()
            }.toSet()
    }
}
