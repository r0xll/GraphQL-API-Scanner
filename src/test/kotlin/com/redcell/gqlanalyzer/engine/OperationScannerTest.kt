package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.MockContext
import com.redcell.gqlanalyzer.checks.SchemaFixtures
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.OperationKind
import com.redcell.gqlanalyzer.model.OperationStatus
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
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
            listOf(rsp(same)), // repeats for every send
            config = CheckConfig(
                authHeadersA = mapOf("Authorization" to "A"),
                authHeadersB = mapOf("Authorization" to "B"),
            ),
            schema = schema,
        )
        val r = OperationScanner().scan(ctx, listOf(ops["QUERY.user"]!!))

        assertTrue(r.findings.any { it.checkId == "op-bola" })
        // primary + identity A + identity B, then the injection pass on the injectable `id` arg
        // (quote + SSTI) — all clean here, so no injection findings.
        assertEquals(5, sent.requests.size)
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

    @Test
    fun `scan records the final probe per operation`() {
        val body = """{"data":{"adminUsers":{"__typename":"User"}}}"""
        val op = ops["QUERY.adminUsers"]!!
        val (ctx, _) = MockContext.build(listOf(rsp(body)), schema = schema)
        val r = OperationScanner().scan(ctx, listOf(op))

        val probe = r.probes[op]
        assertTrue(probe != null)
        assertEquals(body, probe!!.body)
    }

    // ---- v0.14.0: per-operation in-band injection ----

    private fun nnScalar(name: String) = GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "SCALAR", name = name))
    private val RESOLVED_PRODUCT = """{"data":{"product":{"__typename":"Product"}}}"""

    /** Query { product(serial: ProductSerialNumber!): Product } — one custom-scalar injectable arg. */
    private fun customScalarSchema(): SchemaModel {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(GqlField("product", GqlTypeRef(kind = "OBJECT", name = "Product"), args = listOf(GqlInputValue("serial", nnScalar("ProductSerialNumber"))))),
        )
        return SchemaModel("Query", null, null, listOf(query, GqlType("Product", "OBJECT"), GqlType("ProductSerialNumber", "SCALAR")))
    }

    @Test
    fun `error-based injection fires on a custom-scalar arg (sends ride the per-op scan)`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val sqlErr = """{"errors":[{"message":"ERROR: syntax error at or near \"'\""}]}"""
        // baseline (resolved), quote (SQL error), ssti (clean)
        val (ctx, _) = MockContext.build(listOf(rsp(RESOLVED_PRODUCT), rsp(sqlErr), rsp(RESOLVED_PRODUCT)), schema = s)

        val r = OperationScanner().scan(ctx, listOf(op))
        val f = r.findings.single { it.checkId == "op-injection-error" }
        assertEquals("Query.product", f.affectedOperation)
        assertTrue(f.location.endsWith("#Query.product"))
        assertTrue(r.findings.none { it.checkId == "op-injection-ssti" })
    }

    @Test
    fun `ssti injection fires when the arithmetic payload is evaluated`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val evaluated = """{"data":{"product":"49"}}"""
        // baseline (resolved, no 49), quote (clean), ssti (49)
        val (ctx, _) = MockContext.build(listOf(rsp(RESOLVED_PRODUCT), rsp(RESOLVED_PRODUCT), rsp(evaluated)), schema = s)

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals(1, r.findings.count { it.checkId == "op-injection-ssti" })
        assertTrue(r.findings.none { it.checkId == "op-injection-error" })
    }

    @Test
    fun `clean operation yields no injection findings`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val (ctx, _) = MockContext.build(listOf(rsp(RESOLVED_PRODUCT)), schema = s) // repeats
        val r = OperationScanner().scan(ctx, listOf(op))
        assertTrue(r.findings.none { it.checkId.startsWith("op-injection") })
    }

    @Test
    fun `selected mutation is injected — selection is the gate`() {
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(GqlField("updateTag", GqlTypeRef(kind = "SCALAR", name = "Boolean"), args = listOf(GqlInputValue("tag", nnScalar("String"))))),
        )
        val s = SchemaModel("Query", "Mutation", null, listOf(GqlType("Query", "OBJECT"), mutation))
        val op = OperationEnumerator.enumerate(s).first { it.name == "MUTATION.updateTag" }
        val sqlErr = """{"errors":[{"message":"You have an error in your SQL syntax"}]}"""
        // baseline (resolved bool), quote (SQL error), ssti (clean)
        val (ctx, sent) = MockContext.build(listOf(rsp("""{"data":{"updateTag":true}}"""), rsp(sqlErr), rsp("""{"data":{"updateTag":true}}""")), schema = s)

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals("Mutation.updateTag", r.findings.single { it.checkId == "op-injection-error" }.affectedOperation)
        assertTrue(sent.requests.size >= 2) // baseline + at least the quote payload were sent
    }

    @Test
    fun `invalid-input operation sends no injection payloads`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        // An unfixable coercion error -> INVALID_INPUT, no usable hint to synthesize.
        val coercion = """{"errors":[{"message":"Expected value of type \"ProductSerialNumber!\", found \"test\"; bad value."}]}"""
        val (ctx, sent) = MockContext.build(listOf(rsp(coercion)), schema = s)

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals(OperationStatus.INVALID_INPUT, r.statuses[op])
        assertTrue(r.findings.none { it.checkId.startsWith("op-injection") })
        assertEquals(1, sent.requests.size) // only the adaptive probe; no injection sends
    }

    @Test
    fun `injectable arg count is capped`() {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(
                GqlField(
                    "multi", GqlTypeRef(kind = "SCALAR", name = "Boolean"),
                    args = listOf(GqlInputValue("a", nnScalar("String")), GqlInputValue("b", nnScalar("String")), GqlInputValue("c", nnScalar("String"))),
                ),
            ),
        )
        val s = SchemaModel("Query", null, null, listOf(query))
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.multi" }
        val (ctx, sent) = MockContext.build(listOf(rsp("""{"data":{"multi":true}}""")), schema = s) // repeats clean

        OperationScanner(maxInjectableArgs = 2).scan(ctx, listOf(op))
        // 1 adaptive baseline + 2 args × 2 payloads (quote + ssti) = 5; the 3rd arg is never injected.
        assertEquals(5, sent.requests.size)
    }

    @Test
    fun `scoreOperation matches a full scan for the same response`() {
        val body = """{"data":{"adminUsers":{"__typename":"User"}}}"""
        val op = ops["QUERY.adminUsers"]!!
        val (ctx, _) = MockContext.build(listOf(rsp(body)), schema = schema)
        val rr = rsp(body)

        val (status, findings) = OperationScanner().scoreOperation(ctx, op, rr, body)
        assertEquals(OperationStatus.RESOLVED, status)
        assertEquals(1, findings.size)
        assertEquals("op-bfla", findings[0].checkId)
        assertTrue(findings[0].location.endsWith("#Query.adminUsers"))
    }
}
