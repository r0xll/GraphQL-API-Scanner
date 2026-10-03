package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.EngineFingerprints
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API9:2023 (Improper Inventory Management) — server engine fingerprinting
 * (graphw00f-style). Sends a few benign/edge probes and matches the error
 * signatures to name the GraphQL implementation. Knowing the engine sharpens every
 * other check (engine-specific introspection toggles, DoS defaults, injection dialects).
 */
class EngineFingerprintCheck : GraphQLCheck {
    override val id = "engine-fingerprint"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val bodies = PROBES.map { probe ->
            GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(probe))
                .response()?.bodyToString().orEmpty()
        }
        val engine = EngineFingerprints.identify(bodies) ?: return emptyList()

        return listOf(
            Finding(
                name = "GraphQL engine fingerprinted: $engine",
                detail = """
                    Error-message signatures identify the GraphQL server implementation as
                    **$engine**. Engine disclosure lets an attacker target implementation-specific
                    weaknesses (default introspection/debug behaviour, known DoS limits, injection
                    dialects) and tune subsequent attacks precisely.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — technology
                    disclosure to an unauthenticated user.
                """.trimIndent(),
                severity = Severity.LOW,
                confidence = Confidence.FIRM,
                remediation = """
                    Return generic, implementation-agnostic error messages in production and remove
                    engine-identifying strings/headers. This cannot fully prevent fingerprinting but
                    raises the effort required.
                """.trimIndent(),
                evidence = emptyList(),
            ),
        )
    }

    companion object {
        /** Benign/edge probes that elicit engine-distinctive error text. */
        val PROBES = listOf(
            "query { __typename }",                 // baseline
            "query { thisFieldDoesNotExist_x }",    // field-undefined wording
            "query { ",                              // syntax error wording
            "mutation { __typename }",               // mutation-on-query-only wording
        )
    }
}
