package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 — verbose errors. Sends a deliberately malformed operation and
 * inspects the error body for stack traces, framework internals, SQL errors or
 * filesystem paths. Benign probe; no exploitation.
 */
class VerboseErrorCheck : GraphQLCheck {
    override val id = "verbose-errors"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        // Unterminated selection set -> server-side parse/exception path.
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(PROBE))
        val body = rr.response()?.bodyToString().orEmpty()
        val indicators = Heuristics.verboseIndicators(body)
        if (indicators.isEmpty()) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL verbose error messages leak internals",
                detail = """
                    A malformed query triggered an error response disclosing internal details:
                    ${indicators.joinToString("; ")}.
                    Stack traces, framework/ORM names, SQL errors and filesystem paths reveal the
                    technology stack and code structure, aiding targeted exploitation (e.g. picking
                    an injection payload for the disclosed database engine).

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — information
                    disclosure without authentication.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = """
                    Return generic error messages in production and strip `extensions.exception`
                    stack traces (Apollo: `includeStacktraceInErrorResponses: false` / mask with a
                    `formatError` hook; graphql-java: custom `DataFetcherExceptionHandler`). Log the
                    detail server-side only and surface a correlation id to clients.
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        const val PROBE = "{ __typename "
    }
}
