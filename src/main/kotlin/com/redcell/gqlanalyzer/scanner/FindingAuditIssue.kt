package com.redcell.gqlanalyzer.scanner

import burp.api.montoya.scanner.audit.issues.AuditIssue
import com.redcell.gqlanalyzer.model.Finding

/**
 * Maps a [Finding] to a Burp [AuditIssue], preserving evidence and OWASP context.
 * HTML rendering and base-URL resolution are pure (and public) so they are
 * unit-testable without Burp's runtime object factory.
 */
object FindingAuditIssue {

    fun toAuditIssue(finding: Finding): AuditIssue =
        AuditIssue.auditIssue(
            finding.name,
            detailHtml(finding),
            html(finding.remediation),
            baseUrl(finding),
            finding.severity,
            finding.confidence,
            backgroundHtml(finding),
            html(finding.remediation),
            finding.severity,
            *finding.evidence.toTypedArray(),
        )

    fun baseUrl(finding: Finding): String = finding.location.ifEmpty {
        runCatching { finding.evidence.firstOrNull()?.request()?.url() }.getOrNull().orEmpty()
    }

    fun detailHtml(f: Finding): String {
        val tag = buildString {
            append("<b>OWASP:</b> ").append(escape(f.owaspId))
            if (f.checkId.isNotEmpty()) append(" &nbsp;|&nbsp; <b>Check:</b> ").append(escape(f.checkId))
        }
        return "<div>$tag<br><br>${html(f.detail)}</div>"
    }

    fun backgroundHtml(f: Finding): String =
        "<div>GraphQL OWASP API Security Top 10 (2023) — ${escape(f.owaspId)}. " +
            "Detected by the GraphQL OWASP-API Analyzer (proof-level, non-destructive).</div>"

    fun html(text: String): String = escape(text).replace("\n", "<br>")

    fun escape(s: String): String =
        s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
}
