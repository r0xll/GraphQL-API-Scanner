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
}
