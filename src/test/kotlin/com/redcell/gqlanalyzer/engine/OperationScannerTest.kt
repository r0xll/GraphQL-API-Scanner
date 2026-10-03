package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.MockContext
import com.redcell.gqlanalyzer.checks.SchemaFixtures
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.OperationStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OperationScannerTest {

    private val schema = SchemaFixtures.full()
    private val ops = OperationEnumerator.enumerate(schema).associateBy { it.name }

    private fun rsp(body: String) = MockContext.mockResponse(200, body)

    @Test
    fun `bfla fires for a privileged operation that resolves`() {
        val body = """{"data":{"adminUsers":{"__typename":"User"}}}"""
        val (ctx, _) = MockContext.build(listOf(rsp(body)), schema = schema)
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.adminUsers"]!!))

        assertEquals(1, r.findings.size)
        assertEquals("op-bfla", r.findings[0].checkId)
        assertTrue(r.findings[0].location.endsWith("#Query.adminUsers"))
        assertEquals(OperationStatus.RESOLVED, r.statuses[ops["QUERY.adminUsers"]!!])
    }

    @Test
    fun `sensitive field exposure fires when sensitive leaves return`() {
        val body = """{"data":{"me":{"password":"h","token":"t"}}}"""
        val (ctx, sent) = MockContext.build(listOf(rsp(body)), schema = schema)
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.me"]!!))

        assertTrue(r.findings.any { it.checkId == "op-field-authz" })
        // The probe selected the sensitive leaves, not __typename.
        assertTrue(sent.bodies.first().contains("password"))
    }

    @Test
    fun `bola fires across two identities on an id-addressed operation`() {
        val same = """{"data":{"user":{"id":"1"}}}"""
        val (ctx, sent) = MockContext.build(
            listOf(rsp(same), rsp(same), rsp(same)), // primary + identity A + identity B
            config = CheckConfig(
                authHeadersA = mapOf("Authorization" to "A"),
                authHeadersB = mapOf("Authorization" to "B"),
            ),
            schema = schema,
        )
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.user"]!!))

        assertTrue(r.findings.any { it.checkId == "op-bola" })
        assertEquals(3, sent.requests.size) // primary + two identities
    }

    @Test
    fun `bola skipped without two identities`() {
        val (ctx, _) = MockContext.build(listOf(rsp("""{"data":{"user":{"id":"1"}}}""")), schema = schema)
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.user"]!!))
        assertTrue(r.findings.none { it.checkId == "op-bola" })
    }

    @Test
    fun `status classification`() {
        assertEquals(OperationStatus.DENIED, OperationScanner.classify("""{"errors":[{"message":"Forbidden"}]}""", "x", 200))
        assertEquals(OperationStatus.RESOLVED, OperationScanner.classify("""{"data":{"x":1}}""", "x", 200))
        assertEquals(OperationStatus.EMPTY, OperationScanner.classify("""{"data":{"x":null}}""", "x", 200))
        assertEquals(OperationStatus.ERROR, OperationScanner.classify("""{"errors":[{"message":"boom"}]}""", "x", 500))
    }

    @Test
    fun `verbose error tagged to the operation`() {
        val body = """{"errors":[{"message":"NullPointerException at com.app.R.get(R.java:1)"}]}"""
        val (ctx, _) = MockContext.build(listOf(rsp(body)), schema = schema)
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.me"]!!))
        assertTrue(r.findings.any { it.checkId == "op-verbose-errors" && it.location.endsWith("#Query.me") })
    }
}
