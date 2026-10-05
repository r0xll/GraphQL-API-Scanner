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
import com.redcell.gqlanalyzer.transport.InjectionPayloads
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
        // primary + identity A + identity B, then the injection catalog on the injectable `id` leaf.
        assertEquals(3 + InjectionPayloads.inBand.size, sent.requests.size)
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
        // Any payload carrying a quote breaker → SQL error; the clean baseline (serial:"test") → positional.
        val (ctx, _) = MockContext.build(
            listOf(rsp(RESOLVED_PRODUCT)), schema = s,
            responder = { body -> if (body.contains("'")) rsp(sqlErr) else null },
        )

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
        val evaluated = """{"data":{"product":"1337"}}"""
        // EVAL payloads compute 7*191; only those (containing "191") come back evaluated.
        val (ctx, _) = MockContext.build(
            listOf(rsp(RESOLVED_PRODUCT)), schema = s,
            responder = { body -> if (body.contains("191")) rsp(evaluated) else null },
        )

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals(1, r.findings.count { it.checkId == "op-injection-ssti" })
        assertTrue(r.findings.none { it.checkId == "op-injection-error" })
    }

    @Test
    fun `path-traversal read fires on an etc-passwd marker`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val passwd = """{"data":{"product":"root:x:0:0:root:/root:/bin/bash"}}"""
        val (ctx, _) = MockContext.build(
            listOf(rsp(RESOLVED_PRODUCT)), schema = s,
            responder = { body -> if (body.contains("etc/passwd")) rsp(passwd) else null },
        )

        val r = OperationScanner().scan(ctx, listOf(op))
        val f = r.findings.single { it.checkId == "op-injection-file" }
        assertEquals("Query.product", f.affectedOperation)
    }

    @Test
    fun `boolean-based blind fires on a true-false differential`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val data = """{"data":{"product":{"__typename":"Product"}}}"""
        val empty = """{"data":null}"""
        val (ctx, _) = MockContext.build(
            listOf(rsp(RESOLVED_PRODUCT)), schema = s,
            responder = { body ->
                when {
                    body.contains("'1'='1") -> rsp(data)  // TRUE tautology returns data
                    body.contains("'1'='2") -> rsp(empty) // FALSE contradiction returns nothing
                    else -> null
                }
            },
        )

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals(1, r.findings.count { it.checkId == "op-injection-boolean" })
    }

    @Test
    fun `clean operation yields no injection findings`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val (ctx, _) = MockContext.build(listOf(rsp(RESOLVED_PRODUCT)), schema = s) // repeats clean
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
        val (ctx, sent) = MockContext.build(
            listOf(rsp("""{"data":{"updateTag":true}}""")), schema = s,
            responder = { body -> if (body.contains("'")) rsp(sqlErr) else null },
        )

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals("Mutation.updateTag", r.findings.single { it.checkId == "op-injection-error" }.affectedOperation)
        assertTrue(sent.requests.size >= 2) // baseline + at least one injection payload were sent
    }

    @Test
    fun `invalid-input operation still attempts injection (operator wants the evidence)`() {
        val s = customScalarSchema()
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        // An unfixable coercion error -> INVALID_INPUT, no usable hint to synthesize.
        val coercion = """{"errors":[{"message":"Expected value of type \"ProductSerialNumber!\", found \"test\"; bad value."}]}"""
        val (ctx, sent) = MockContext.build(listOf(rsp(coercion)), schema = s) // repeats

        val r = OperationScanner().scan(ctx, listOf(op))
        assertEquals(OperationStatus.INVALID_INPUT, r.statuses[op])
        // 1 adaptive probe + the full catalog on `serial` — the operator sees the attempts in Logger.
        assertEquals(1 + InjectionPayloads.inBand.size, sent.requests.size)
        // A coercion error is not an injection signature, so nothing is (falsely) reported.
        assertTrue(r.findings.none { it.checkId.startsWith("op-injection") })
    }

    @Test
    fun `injection point count is capped`() {
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

        OperationScanner(maxInjectionPoints = 2).scan(ctx, listOf(op))
        // 1 adaptive baseline + 2 capped leaves × the full catalog; the 3rd arg is never injected.
        assertEquals(1 + 2 * InjectionPayloads.inBand.size, sent.requests.size)
    }

    @Test
    fun `injects into nested fields of an input-object argument`() {
        // mutation { evt(event: EventInput!) }  with string/custom-scalar leaves nested in the object.
        val input = GqlType(
            "EventInput", "INPUT_OBJECT",
            inputFields = listOf(
                GqlInputValue("id", nnScalar("ID")),
                GqlInputValue("profileId", nnScalar("String")),
                GqlInputValue("timestamp", nnScalar("DateTime")),
                GqlInputValue("value", nnScalar("Float")),
                GqlInputValue("type", GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "ENUM", name = "Cat"))),
            ),
        )
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(GqlField("evt", GqlTypeRef(kind = "SCALAR", name = "Boolean"), args = listOf(GqlInputValue("event", GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "INPUT_OBJECT", name = "EventInput")))))),
        )
        val cat = GqlType("Cat", "ENUM", enumValues = listOf("A"))
        val s = SchemaModel("Query", "Mutation", null, listOf(GqlType("Query", "OBJECT"), mutation, input, cat, GqlType("DateTime", "SCALAR")))
        val op = OperationEnumerator.enumerate(s).first { it.name == "MUTATION.evt" }

        // Fire a SQL error only for the quote payload landing in event.profileId (siblings stay valid).
        val clean = """{"data":{"evt":true}}"""
        val sqlErr = """{"errors":[{"message":"ERROR: syntax error at or near \"'\""}]}"""
        val (ctx, sent) = MockContext.build(
            listOf(rsp(clean)), schema = s,
            responder = { body -> if (body.contains("""profileId: \"'\"""")) rsp(sqlErr) else null },
        )

        val r = OperationScanner().scan(ctx, listOf(op))
        val f = r.findings.single { it.checkId == "op-injection-error" }
        assertTrue(f.name.contains("event.profileId"))
        assertEquals("Mutation.evt", f.affectedOperation)
        // The firing request carried the payload at the nested field with siblings kept valid.
        assertTrue(sent.bodies.any { it.contains("""profileId: \"'\"""") && it.contains("timestamp:") && it.contains("id:") })
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
