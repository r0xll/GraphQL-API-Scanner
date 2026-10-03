package com.redcell.gqlanalyzer.checks

import burp.api.montoya.MontoyaApi
import com.redcell.gqlanalyzer.checks.impl.ActiveSsrfCheck
import com.redcell.gqlanalyzer.checks.impl.OobCanaryInjectionCheck
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import com.redcell.gqlanalyzer.transport.OobClient
import com.redcell.gqlanalyzer.transport.OobPayload
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase8ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)

    private val str = GqlTypeRef(kind = "SCALAR", name = "String")

    /** Query { fetch(url: String): String, note(text: String): String } */
    private fun schema(): SchemaModel {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(
                GqlField("fetch", str, args = listOf(GqlInputValue("url", str))),
                GqlField("note", str, args = listOf(GqlInputValue("text", str))),
            ),
        )
        return SchemaModel("Query", null, null, listOf(query))
    }

    /** Fake OOB client: mints incrementing ids; [firedIndices] decide which payloads "fire". */
    private class FakeOob(val availableFlag: Boolean, val fireFirst: Boolean) : OobClient {
        val generated = mutableListOf<OobPayload>()
        override fun available() = availableFlag
        override fun generate(): OobPayload {
            val p = OobPayload("h${generated.size}.oast.example", "id${generated.size}")
            generated += p
            return p
        }
        override fun firedIds(): Set<String> =
            if (fireFirst && generated.isNotEmpty()) setOf(generated.first().id) else emptySet()
    }

    @Test
    fun `active ssrf confirms when the url-arg payload fires`() {
        val fake = FakeOob(availableFlag = true, fireFirst = true)
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"fetch":"ok"}}""")), schema = schema())
        val check = ActiveSsrfCheck(oobFactory = { _: MontoyaApi -> fake }, pollAttempts = 1, pollDelayMs = 0)
        val f = check.run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].name.contains("fetch"))
        // the SSRF-named 'url' arg was injected with a collaborator URL
        assertTrue(sent.bodies.any { it.contains("http://h0.oast.example/") })
    }

    @Test
    fun `active ssrf silent when no interaction fires`() {
        val fake = FakeOob(availableFlag = true, fireFirst = false)
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"data":{"fetch":"ok"}}""")), schema = schema())
        val check = ActiveSsrfCheck(oobFactory = { _: MontoyaApi -> fake }, pollAttempts = 1, pollDelayMs = 0)
        assertTrue(check.run(ctx).isEmpty())
    }

    @Test
    fun `active ssrf skipped when collaborator unavailable`() {
        val fake = FakeOob(availableFlag = false, fireFirst = true)
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = schema())
        val check = ActiveSsrfCheck(oobFactory = { _: MontoyaApi -> fake }, pollAttempts = 1, pollDelayMs = 0)
        assertTrue(check.run(ctx).isEmpty())
        assertTrue(sent.requests.isEmpty())
    }

    @Test
    fun `oob canary targets non-ssrf string args and confirms on fire`() {
        val fake = FakeOob(availableFlag = true, fireFirst = true)
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"note":"ok"}}""")), schema = schema())
        val check = OobCanaryInjectionCheck(oobFactory = { _: MontoyaApi -> fake }, pollAttempts = 1, pollDelayMs = 0)
        val f = check.run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].name.contains("note")) // 'url' excluded (owned by ActiveSsrfCheck)
        assertTrue(sent.bodies.any { it.contains("text:") && it.contains("oast.example") })
    }
}
