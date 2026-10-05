package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.engine.OperationEnumerator
import com.redcell.gqlanalyzer.engine.OperationScanner
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

/**
 * OOB/Collaborator confirmation, now driven by the per-operation scan (v0.16.0) rather than the
 * old endpoint checks. Uses a fake collaborator so no Montoya runtime is needed.
 */
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

    /** Fake OOB client: mints incrementing payloads; [fireFirst] fires only the first minted id. */
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

    private fun scanner(fake: FakeOob) =
        OperationScanner(oobFactory = { _ -> fake }, pollAttempts = 1, pollDelayMs = 0)

    private fun ops(s: SchemaModel) = OperationEnumerator.enumerate(s).associateBy { it.name }

    @Test
    fun `confirmed SSRF on a url-named leaf when its OOB payload fires`() {
        val s = schema()
        val fake = FakeOob(availableFlag = true, fireFirst = true)
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"fetch":"ok"}}""")), schema = s)

        // Scan fetch first so its url leaf mints the first (firing) payload.
        val r = scanner(fake).scan(ctx, listOf(ops(s)["QUERY.fetch"]!!, ops(s)["QUERY.note"]!!))

        val f = r.findings.single { it.checkId == "op-ssrf-confirmed" }
        assertTrue(f.name.contains("fetch"))
        assertTrue(f.location.endsWith("(url)"))
        assertTrue(sent.bodies.any { it.contains("http://h0.oast.example/") })
    }

    @Test
    fun `confirmed generic OOB on a non-url leaf`() {
        val s = schema()
        val fake = FakeOob(availableFlag = true, fireFirst = true)
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"data":{"note":"ok"}}""")), schema = s)

        val r = scanner(fake).scan(ctx, listOf(ops(s)["QUERY.note"]!!))
        val f = r.findings.single { it.checkId == "op-oob-confirmed" }
        assertTrue(f.name.contains("note"))
        assertTrue(f.location.endsWith("(text)"))
    }

    @Test
    fun `no OOB findings and no collaborator payloads when unavailable`() {
        val s = schema()
        val fake = FakeOob(availableFlag = false, fireFirst = true)
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = s)

        val r = scanner(fake).scan(ctx, listOf(ops(s)["QUERY.fetch"]!!))
        assertTrue(r.findings.none { it.checkId == "op-ssrf-confirmed" || it.checkId == "op-oob-confirmed" })
        assertTrue(sent.bodies.none { it.contains("oast.example") }) // no OOB payload sent
    }
}
