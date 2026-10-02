package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.BatchingCheck
import com.redcell.gqlanalyzer.checks.impl.CsrfCheck
import com.redcell.gqlanalyzer.checks.impl.IntrospectionCheck
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.transport.AliasBatch
import com.redcell.gqlanalyzer.transport.GraphQLResponses
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase2ChecksTest {

    // ---- IntrospectionCheck (API9) ----

    private val schemaBody = """
        {"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":null,
        "subscriptionType":null,"types":[{"kind":"OBJECT","name":"Query","fields":[
        {"name":"me","args":[],"type":{"kind":"OBJECT","name":"User","ofType":null}}]}]}}}
    """.trimIndent()

    @Test
    fun `introspection fires when schema returned`() {
        val (ctx, _) = MockContext.build(listOf(MockContext.mockResponse(200, schemaBody)))
        val f = IntrospectionCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals("API9:2023", IntrospectionCheck().owaspId)
        assertTrue(f[0].evidence.isNotEmpty())
    }

    @Test
    fun `introspection silent when disabled`() {
        val disabled = """{"data":null,"errors":[{"message":"introspection is disabled"}]}"""
        val (ctx, _) = MockContext.build(listOf(MockContext.mockResponse(200, disabled)))
        assertTrue(IntrospectionCheck().run(ctx).isEmpty())
    }

    // ---- CsrfCheck (API8) ----

    @Test
    fun `csrf fires when GET accepted, reports both when both accepted`() {
        val ok = """{"data":{"__typename":"Query"}}"""
        val bad = """{"errors":[{"message":"must POST"}]}"""
        // send order: GET then form
        val (ctxGetOnly, _) = MockContext.build(
            listOf(MockContext.mockResponse(200, ok), MockContext.mockResponse(400, bad)),
        )
        val fGet = CsrfCheck().run(ctxGetOnly)
        assertEquals(1, fGet.size)
        assertTrue(fGet[0].name.contains("GET"))

        val (ctxBoth, _) = MockContext.build(
            listOf(MockContext.mockResponse(200, ok), MockContext.mockResponse(200, ok)),
        )
        val fBoth = CsrfCheck().run(ctxBoth)
        assertEquals(2, fBoth[0].evidence.size)
    }

    @Test
    fun `csrf silent when neither vector accepted`() {
        val bad = """{"errors":[{"message":"must POST json"}]}"""
        val (ctx, _) = MockContext.build(
            listOf(MockContext.mockResponse(400, bad), MockContext.mockResponse(400, bad)),
        )
        assertTrue(CsrfCheck().run(ctx).isEmpty())
    }

    // ---- BatchingCheck (API4) ----

    private fun aliasResolvedBody(n: Int): String {
        val (_, names) = AliasBatch.aliasQuery(n)
        val fields = names.joinToString(",") { "\"$it\":\"Query\"" }
        return """{"data":{$fields}}"""
    }

    private fun arrayResolvedBody(n: Int): String =
        "[" + (0 until n).joinToString(",") { """{"data":{"__typename":"Query"}}""" } + "]"

    @Test
    fun `batching fires when all aliases and all array ops resolve`() {
        val (ctx, _) = MockContext.build(
            listOf(
                MockContext.mockResponse(200, aliasResolvedBody(10)),
                MockContext.mockResponse(200, arrayResolvedBody(10)),
            ),
        )
        val f = BatchingCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(2, f[0].evidence.size)
        assertTrue(f[0].remediation.contains("rate limit", ignoreCase = true))
    }

    @Test
    fun `batching silent when aliases only partially resolve`() {
        // alias response missing some keys; array response not an array
        val (ctx, _) = MockContext.build(
            listOf(
                MockContext.mockResponse(200, aliasResolvedBody(3)), // fewer than requested 10
                MockContext.mockResponse(200, """{"data":{"__typename":"Query"}}"""),
            ),
        )
        assertTrue(BatchingCheck().run(ctx).isEmpty())
    }

    @Test
    fun `batching never exceeds proof cap of 10 even if config asks for more`() {
        val (ctx, sent) = MockContext.build(
            listOf(
                MockContext.mockResponse(200, aliasResolvedBody(10)),
                MockContext.mockResponse(200, arrayResolvedBody(10)),
            ),
            config = CheckConfig(maxBatch = 10_000),
        )
        BatchingCheck().run(ctx)
        // First send is the alias query; it must contain a9 but never a10.
        val aliasBody = sent.bodies.first()
        assertTrue(aliasBody.contains("a9:"))
        assertTrue(!aliasBody.contains("a10:"))
    }

    // ---- pure response predicates ----

    @Test
    fun `aliasesResolved requires every alias present and non-null`() {
        assertTrue(GraphQLResponses.aliasesResolved("""{"data":{"a0":1,"a1":2}}""", listOf("a0", "a1")))
        assertTrue(!GraphQLResponses.aliasesResolved("""{"data":{"a0":1,"a1":null}}""", listOf("a0", "a1")))
        assertTrue(!GraphQLResponses.aliasesResolved("""{"data":{"a0":1}}""", listOf("a0", "a1")))
    }

    @Test
    fun `arrayBatchResolved requires n resolved elements`() {
        assertTrue(GraphQLResponses.arrayBatchResolved("""[{"data":{}},{"data":{}}]""", 2))
        assertTrue(!GraphQLResponses.arrayBatchResolved("""[{"data":{}},{"errors":[]}]""", 2))
        assertTrue(!GraphQLResponses.arrayBatchResolved("""{"data":{}}""", 2))
    }
}
