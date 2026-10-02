package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 (Security Misconfiguration) — CORS simple-request bypass. Sends a benign
 * `{__typename}` JSON envelope with `Content-Type: text/plain`, which browsers treat
 * as a CORS "simple request" (no preflight). If the server executes it, the operation
 * is forgeable cross-site without the browser ever sending an OPTIONS preflight.
 */
class ContentTypeBypassCheck : GraphQLCheck {
    override val id = "content-type-bypass"
    override val owaspId = "API8:2023"

    private val probe = "{__typename}"

    override fun run(ctx: CheckContext): List<Finding> {
        val body = GraphQLHttp.queryEnvelope(probe)
        val rr = GraphQLHttp.postText(ctx.api, ctx.request, body)
        if (!CsrfCheck.accepted(rr)) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL executed as text/plain (CORS preflight bypass)",
                detail = """
                    The endpoint executed a GraphQL operation sent with `Content-Type: text/plain`.
                    Browsers classify such a POST as a CORS "simple request" and send it without a
                    preflight, so an attacker page can deliver it cross-site in a logged-in victim's
                    session (cookie auth). If any state-changing mutation accepts this content type,
                    it is CSRF-able without preflight protection.

                    Proof used a benign `{__typename}`; no mutation was issued.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4, Medium) — impact depends on
                    which mutations share the vector.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Reject non-JSON content types for GraphQL (enforce `application/json`), enable
                    CSRF prevention (Apollo `csrfPrevention: true` / require `Apollo-Require-Preflight`
                    or a custom header), and use SameSite=strict/lax session cookies.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }
}
