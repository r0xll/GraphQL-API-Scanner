package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API9:2023 / API8 — Automatic Persisted Queries (APQ) detection. Sends an APQ
 * lookup (a `persistedQuery` hash with no query); an Apollo-style
 * `PersistedQueryNotFound` reply confirms APQ is enabled. Informational: APQ widens
 * the attack surface (hash probing, cache behaviour, CDN interactions).
 */
class ApqDetectionCheck : GraphQLCheck {
    override val id = "apq-detection"
    override val owaspId = "API9:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, APQ_PROBE)
        val body = rr.response()?.bodyToString().orEmpty()
        if (!apqEnabled(body)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL Automatic Persisted Queries (APQ) enabled",
                detail = """
                    An APQ lookup (persisted-query hash, no query body) returned
                    `PersistedQueryNotFound`, confirming APQ is enabled. APQ adds a hash-addressed
                    query cache that can interact with CDN caching and introduces hash-probing and
                    cache-poisoning surface worth reviewing.

                    CVSS v3.1: not scored — informational attack-surface disclosure.
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.FIRM,
                remediation = """
                    If APQ is not required, disable it. If it is, ensure persisted-query registration
                    is authenticated/allow-listed, and that per-user/authenticated responses are not
                    cached by shared CDNs keyed only on the APQ hash.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        /** APQ lookup envelope: version 1 + a well-known empty-ish sha256, no query. */
        val APQ_PROBE =
            """{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"0000000000000000000000000000000000000000000000000000000000000000"}}}"""

        /**
         * APQ is on when the server asks for the full query for an unknown hash
         * (`PersistedQueryNotFound`). `PersistedQueryNotSupported` means APQ is off.
         */
        fun apqEnabled(body: String): Boolean =
            body.contains("PersistedQueryNotFound", ignoreCase = true)
    }
}
