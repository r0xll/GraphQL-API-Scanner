package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 — CORS misconfiguration. Sends a benign query with a foreign `Origin`
 * and checks whether the response reflects that origin (or `*`) in
 * Access-Control-Allow-Origin alongside Access-Control-Allow-Credentials: true — a
 * credentialed cross-origin read of the GraphQL API.
 */
class CorsCheck : GraphQLCheck {
    override val id = "cors"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(
            ctx.api, ctx.request, GraphQLHttp.queryEnvelope("query { __typename }"),
            extraHeaders = mapOf("Origin" to TEST_ORIGIN),
        )
        val resp = rr.response() ?: return emptyList()
        val acao = resp.headerValue("Access-Control-Allow-Origin")
        val acac = resp.headerValue("Access-Control-Allow-Credentials")
        if (!Heuristics.corsMisconfig(acao, acac, TEST_ORIGIN)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL CORS misconfiguration (credentialed cross-origin read)",
                detail = """
                    The endpoint reflected the attacker-supplied origin in
                    `Access-Control-Allow-Origin: $acao` with
                    `Access-Control-Allow-Credentials: $acac`. A malicious site can therefore read
                    authenticated GraphQL responses in a logged-in victim's browser (cookie auth),
                    exfiltrating any data the victim can query.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N (6.5, Medium) — user-interaction
                    (victim visits attacker page); confidentiality impact scales with query reach.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = """
                    Do not reflect arbitrary origins. Allow-list exact trusted origins, and never
                    combine `Access-Control-Allow-Credentials: true` with a reflected or wildcard
                    origin. For token (non-cookie) auth, avoid credentialed CORS entirely.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        const val TEST_ORIGIN = "https://evil.example"
    }
}
