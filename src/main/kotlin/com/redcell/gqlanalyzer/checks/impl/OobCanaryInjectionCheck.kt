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
 * A03 Injection / API7 — OOB canary sweep. Places a unique Collaborator URL into
 * every String/ID argument on READ-ONLY root query fields that the SSRF check did
 * not already cover, and reports any that fire out-of-band. This catches server-side
 * dereference / blind-injection surface on arguments whose names don't look URL-ish.
 * Payloads are canary URLs only — non-destructive. Query-root only; Collaborator-gated.
 */
class OobCanaryInjectionCheck(
    private val oobFactory: (MontoyaApi) -> OobClient = ::BurpOobClient,
    private val pollAttempts: Int = 6,
    private val pollDelayMs: Long = 2000,
) : GraphQLCheck {
    override val id = "oob-canary-injection"
    override val owaspId = "API7:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val queryType = schema.queryType() ?: return emptyList()
        val oob = oobFactory(ctx.api)
        if (!oob.available()) return emptyList()

        // String/ID args on root query fields, excluding SSRF-named ones (ActiveSsrfCheck owns those).
        val points = Heuristics.injectionInsertionPoints(schema)
            .filter { it.parentType == queryType.name && !Heuristics.isSsrfArg(it.arg) }
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
                name = "Confirmed out-of-band dereference on $label",
                detail = """
                    A canary Collaborator URL placed in `$label` caused an out-of-band interaction
                    from the server. The argument is not obviously URL-shaped, so the backend is
                    dereferencing attacker-controlled input somewhere (SSRF via an internal client,
                    blind SSTI/XXE, or a URL-consuming downstream call). Confirm the sink and impact.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2, High) baseline for a
                    confirmed server-side fetch; adjust to the identified sink.
                """.trimIndent(),
                severity = Severity.HIGH,
                confidence = Confidence.CERTAIN,
                remediation = """
                    Treat all argument values as untrusted: do not pass them to URL fetchers,
                    template engines or XML parsers without validation/allow-listing; disable external
                    entity resolution; and apply the SSRF egress controls above to every outbound call.
                """.trimIndent(),
                evidence = listOf(evidence),
                affectedOperation = label,
                location = if (url.isEmpty()) "" else "$url#$label",
            )
        }
    }
}
