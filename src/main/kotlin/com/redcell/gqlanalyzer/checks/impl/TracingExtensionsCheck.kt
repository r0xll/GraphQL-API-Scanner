package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * API8:2023 — performance/tracing data leaked in response `extensions`. A normal
 * query whose response carries `tracing`/`apollo`/`metrics` extensions discloses
 * resolver timings and internal structure useful for targeting.
 */
class TracingExtensionsCheck : GraphQLCheck {
    override val id = "tracing-extensions"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val rr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope("query { __typename }"))
        val keys = GraphQLHttp.extensionsKeys(rr.response()?.bodyToString().orEmpty())
        val leaky = keys.filter { it.lowercase() in LEAKY_KEYS }
        if (leaky.isEmpty()) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL response leaks tracing/perf extensions (${leaky.joinToString(", ")})",
                detail = """
                    The response `extensions` object exposes ${leaky.joinToString(", ")}. Tracing and
                    metrics reveal per-resolver timings, backend structure and query plans — a debug
                    feature that should not reach production clients.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium) — information
                    disclosure without authentication.
                """.trimIndent(),
                severity = Severity.LOW,
                confidence = Confidence.FIRM,
                remediation = """
                    Disable tracing/metrics extensions in production (Apollo: remove the inline-trace /
                    tracing plugin or set it to internal-only; strip `extensions` from client
                    responses at the gateway).
                """.trimIndent(),
                evidence = listOf(rr),
            ),
        )
    }

    companion object {
        val LEAKY_KEYS = setOf("tracing", "apollo", "metrics", "ftv1", "timing")
    }
}
