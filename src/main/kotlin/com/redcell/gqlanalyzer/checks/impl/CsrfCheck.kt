package com.redcell.gqlanalyzer.checks.impl

import burp.api.montoya.http.message.HttpRequestResponse
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 (Security Misconfiguration) — GraphQL CSRF. Fires if the endpoint
 * executes a query sent over GET (?query=) or as application/x-www-form-urlencoded,
 * both of which are forgeable cross-site (no preflight / simple request).
 * Proof uses a benign `{__typename}` — never a mutation.
 */
class CsrfCheck : GraphQLCheck {
    override val id = "csrf"
    override val owaspId = "API8:2023"

    private val probe = "{__typename}"

    override fun run(ctx: CheckContext): List<Finding> {
        val getRR = GraphQLHttp.getWithQuery(ctx.api, ctx.request, probe)
        val formRR = GraphQLHttp.postForm(ctx.api, ctx.request, probe)

        val getOk = accepted(getRR)
        val formOk = accepted(formRR)
        if (!getOk && !formOk) return emptyList()

        val vectors = buildList {
            if (getOk) add("HTTP GET with `?query=`")
            if (formOk) add("POST `application/x-www-form-urlencoded`")
        }
        val evidence = buildList {
            if (getOk) add(getRR)
            if (formOk) add(formRR)
        }

        return listOf(
            Finding(
                name = "GraphQL CSRF: query executed over ${vectors.joinToString(" and ")}",
                detail = """
                    The endpoint executed a GraphQL operation delivered via ${vectors.joinToString(" and ")}.
                    These delivery methods are cross-site forgeable: a GET can be triggered from an
                    `<img>`/`<link>`, and a form-urlencoded POST is a CORS "simple request" that fires
                    without a preflight. If any state-changing mutation is reachable the same way, an
                    attacker page can drive it in a logged-in victim's session (cookie-based auth).

                    Proof used a benign `{__typename}` only; no mutation was issued.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N (5.4, Medium) — user-interaction
                    (victim visits attacker page); impact depends on which mutations share the vector.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Accept GraphQL only over POST with `Content-Type: application/json` and reject
                    GET and form-encoded operations (Apollo CSRF prevention / `csrfPrevention: true`).
                    Add a CSRF token or require a custom header (e.g. `X-Apollo-Operation-Name`,
                    `Apollo-Require-Preflight`) so requests cannot be forged as CORS simple requests,
                    and prefer SameSite=strict/lax session cookies.
                """.trimIndent(),
                evidence = evidence,
            ),
        )
    }

    companion object {
        /** Pure: a 2xx response whose body carries non-null `data`. */
        fun accepted(rr: HttpRequestResponse): Boolean {
            val resp = rr.response() ?: return false
            return resp.statusCode().toInt() in 200..299 && GraphQLHttp.hasData(resp.bodyToString())
        }
    }
}
