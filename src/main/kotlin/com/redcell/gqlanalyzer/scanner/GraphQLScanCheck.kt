package com.redcell.gqlanalyzer.scanner

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.AuditResult
import burp.api.montoya.scanner.ConsolidationAction
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity
import burp.api.montoya.scanner.scancheck.PassiveScanCheck
import com.redcell.gqlanalyzer.detection.GraphQLFingerprint

/**
 * Passive scan check (modern Montoya `PassiveScanCheck`). Raises a single
 * INFORMATION issue when a request/response fingerprints as GraphQL. It never
 * fires the active OWASP checks automatically — those are operator-driven from
 * the tab/context menu, keeping scanning proof-level and non-surprising.
 */
class GraphQLScanCheck : PassiveScanCheck {

    override fun checkName(): String = "GraphQL endpoint detection"

    override fun doCheck(baseRequestResponse: HttpRequestResponse): AuditResult {
        val request = baseRequestResponse.request() ?: return AuditResult.auditResult()
        val responseBody = baseRequestResponse.response()?.bodyToString().orEmpty()
        val detection = GraphQLFingerprint.classify(
            path = request.path(),
            requestBody = request.bodyToString(),
            responseBody = responseBody,
        )
        if (!detection.isGraphQL) return AuditResult.auditResult()

        val issue = AuditIssue.auditIssue(
            "GraphQL endpoint detected",
            "<div>A GraphQL endpoint was identified passively.<br>Signals: " +
                detection.reasons.joinToString("; ") +
                ".<br><br>Use the <b>GraphQL OWASP-API Analyzer</b> tab or the context-menu action to " +
                "run the OWASP API Top 10 checks against this endpoint.</div>",
            "<div>Confirm the endpoint is intended to be exposed and inventoried.</div>",
            runCatching { request.url() }.getOrDefault(request.path()),
            AuditIssueSeverity.INFORMATION,
            AuditIssueConfidence.FIRM,
            "<div>GraphQL endpoints warrant OWASP API Top 10 review.</div>",
            "<div>See the GraphQL Analyzer findings.</div>",
            AuditIssueSeverity.INFORMATION,
            baseRequestResponse,
        )
        return AuditResult.auditResult(issue)
    }

    override fun consolidateIssues(newIssue: AuditIssue, existingIssue: AuditIssue): ConsolidationAction =
        if (newIssue.name() == existingIssue.name() && newIssue.baseUrl() == existingIssue.baseUrl()) {
            ConsolidationAction.KEEP_EXISTING
        } else {
            ConsolidationAction.KEEP_BOTH
        }
}
