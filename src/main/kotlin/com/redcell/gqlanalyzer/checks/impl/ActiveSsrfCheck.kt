package com.redcell.gqlanalyzer.checks.impl

import burp.api.montoya.MontoyaApi
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.BurpOobClient
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.OobClient
import com.redcell.gqlanalyzer.transport.OobScanner
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * API7:2023 — CONFIRMED SSRF via Burp Collaborator. Injects a unique Collaborator
 * URL into each SSRF-named argument on a READ-ONLY root query field and reports only
 * the arguments whose payload actually received an out-of-band interaction. This
 * upgrades the static SSRF seeder to confirmation. Query-root only (never fires a
 * mutation); runs only when Collaborator is available and the operator scans.
 */
class ActiveSsrfCheck(
    private val oobFactory: (MontoyaApi) -> OobClient = ::BurpOobClient,
    private val pollAttempts: Int = 6,
    private val pollDelayMs: Long = 2000,
) : GraphQLCheck {
    override val id = "active-ssrf"
    override val owaspId = "API7:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val queryType = schema.queryType() ?: return emptyList()
        val oob = oobFactory(ctx.api)
        if (!oob.available()) return emptyList()

        // SSRF-named String/ID args on root query fields only (read-only).
        val points = Heuristics.ssrfInsertionPoints(schema).filter { it.parentType == queryType.name }
        if (points.isEmpty()) return emptyList()

        val targets = points.mapNotNull { p ->
            val field = queryType.fields.firstOrNull { it.name == p.field } ?: return@mapNotNull null
            OobScanner.Target("${p.parentType}.${p.field}(${p.arg})") { host ->
                val doc = QueryBuilder.injectedQuery(schema, field, p.arg, "http://$host/")
                GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc))
            }
        }

        val url = runCatching { ctx.request.url() }.getOrNull().orEmpty()
        val fired = OobScanner(oob, pollAttempts, pollDelayMs).run(targets)
        return fired.map { (label, evidence) ->
            Finding(
                name = "Confirmed SSRF on $label (out-of-band interaction)",
                detail = """
                    Injecting a unique Burp Collaborator URL into `$label` triggered an out-of-band
                    interaction from the server — confirming it fetches attacker-controlled URLs
                    (SSRF). Unlike the static SSRF seeder, this is observed, not inferred.

                    Next steps (per ROE): pivot to internal targets (cloud metadata
                    169.254.169.254, 127.0.0.1, internal hostnames) to establish impact.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2, High) — confirmed
                    server-side request forgery reachable unauthenticated; adjust to context.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Allow-list outbound URLs (scheme/host), resolve-and-pin to permitted IP ranges,
                    block link-local/loopback/metadata addresses, and disable redirects on
                    server-side fetches. Prefer an egress proxy with an explicit allow-list.
                """.trimIndent(),
                evidence = listOf(evidence),
                affectedOperation = label,
                location = if (url.isEmpty()) "" else "$url#$label",
            )
        }
    }
}
