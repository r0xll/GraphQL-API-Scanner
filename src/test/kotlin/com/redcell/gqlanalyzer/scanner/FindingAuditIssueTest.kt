package com.redcell.gqlanalyzer.scanner

import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class FindingAuditIssueTest {

    private val finding = Finding(
        name = "Test finding",
        detail = "line one\n<script>alert(1)</script>",
        severity = Severity.HIGH,
        confidence = Confidence.FIRM,
        remediation = "fix it",
        checkId = "bola",
        owaspId = "API1:2023",
        location = "https://target.example/graphql",
    )

    @Test
    fun `detail html escapes and shows owasp and check tags`() {
        val html = FindingAuditIssue.detailHtml(finding)
        assertTrue(html.contains("API1:2023"))
        assertTrue(html.contains("bola"))
        assertTrue(html.contains("&lt;script&gt;")) // escaped, not raw
        assertTrue(!html.contains("<script>"))
        assertTrue(html.contains("line one<br>")) // newline -> <br>
    }

    @Test
    fun `base url prefers location`() {
        assertEquals("https://target.example/graphql", FindingAuditIssue.baseUrl(finding))
    }

    @Test
    fun `escape handles ampersands`() {
        assertEquals("a &amp;&amp; b", FindingAuditIssue.escape("a && b"))
    }

    @Test
    fun `base url appends affected operation when location has no fragment`() {
        val f = finding.copy(affectedOperation = "Query.user")
        assertEquals("https://target.example/graphql#Query.user", FindingAuditIssue.baseUrl(f))
    }

    @Test
    fun `base url does not double-append when location already has a fragment`() {
        val f = finding.copy(location = "https://t/graphql#QUERY.user", affectedOperation = "Query.user")
        assertEquals("https://t/graphql#QUERY.user", FindingAuditIssue.baseUrl(f))
    }

    @Test
    fun `detail html shows affected operation line when set`() {
        val html = FindingAuditIssue.detailHtml(finding.copy(affectedOperation = "Mutation.updateUser"))
        assertTrue(html.contains("Affected operation:"))
        assertTrue(html.contains("Mutation.updateUser"))
    }

    @Test
    fun `endpoint-wide finding has no affected-operation line and bare url`() {
        assertTrue(!FindingAuditIssue.detailHtml(finding).contains("Affected operation"))
        assertEquals("https://target.example/graphql", FindingAuditIssue.baseUrl(finding))
    }
}
