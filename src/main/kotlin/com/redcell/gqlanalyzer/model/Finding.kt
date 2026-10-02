package com.redcell.gqlanalyzer.model

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity

/** Reuse Burp's own enums so Finding -> AuditIssue mapping is lossless. */
typealias Severity = AuditIssueSeverity
typealias Confidence = AuditIssueConfidence

/**
 * A single check result. `checkId`/`owaspId`/`location` are stamped by the
 * [com.redcell.gqlanalyzer.engine.CheckEngine] from the producing check, so
 * check implementations may leave them at their defaults.
 */
data class Finding(
    val name: String,
    val detail: String,
    val severity: Severity,
    val confidence: Confidence,
    val remediation: String,
    val evidence: List<HttpRequestResponse> = emptyList(),
    val checkId: String = "",
    val owaspId: String = "",
    val location: String = "",
)
