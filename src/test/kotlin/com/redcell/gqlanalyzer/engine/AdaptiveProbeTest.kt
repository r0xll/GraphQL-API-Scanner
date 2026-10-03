package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.MockContext
import com.redcell.gqlanalyzer.model.OperationStatus
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AdaptiveProbeTest {

    private fun rsp(body: String) = MockContext.mockResponse(200, body)
    private fun nn(name: String) = GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "SCALAR", name = name))

    /** Query { product(serial: ProductSerialNumber!): Product } */
    private fun schema(scalar: String): SchemaModel {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(GqlField("product", GqlTypeRef(kind = "OBJECT", name = "Product"), args = listOf(GqlInputValue("serial", nn(scalar))))),
        )
        return SchemaModel("Query", null, null, listOf(query, GqlType("Product", "OBJECT"), GqlType(scalar, "SCALAR")))
    }

    @Test
    fun `adapts to a scalar coercion error and resolves on retry`() {
        val s = schema("ProductSerialNumber")
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        val coercion = """{"errors":[{"message":"Expected value of type \"ProductSerialNumber!\", found \"test\"; must be a string that is exactly 16 characters long where each character is parsable as an integer."}]}"""
        val resolved = """{"data":{"product":{"__typename":"Product"}}}"""

        val (ctx, sent) = MockContext.build(listOf(rsp(coercion), rsp(resolved)), schema = s)
        val r = OperationScanner(maxInputRetries = 3).scan(ctx, listOf(op))

        assertEquals(OperationStatus.RESOLVED, r.statuses[op])
        assertEquals(2, sent.requests.size) // primary + one adaptive retry
        assertTrue(!sent.bodies.first().contains("0000000000000000")) // first try used the dumb placeholder
        assertTrue(sent.bodies.last().contains("0000000000000000")) // retry used the mined value
    }

    @Test
    fun `unsatisfiable scalar ends as INVALID_INPUT, not ERROR, and is bounded`() {
        val s = schema("Weird")
        val op = OperationEnumerator.enumerate(s).first { it.name == "QUERY.product" }
        // Coercion error whose type isn't in the table and carries no usable hint.
        val coercion = """{"errors":[{"message":"Expected value of type \"Weird!\", found \"test\"; bad value."}]}"""

        val (ctx, sent) = MockContext.build(listOf(rsp(coercion)), schema = s)
        val r = OperationScanner(maxInputRetries = 3).scan(ctx, listOf(op))

        assertEquals(OperationStatus.INVALID_INPUT, r.statuses[op])
        assertEquals(1, sent.requests.size) // no progress possible -> no wasted retries
    }

    @Test
    fun `classify maps coercion errors to INVALID_INPUT`() {
        val coercion = """{"errors":[{"message":"Expected value of type \"DateTime!\", found \"test\"; cannot represent"}]}"""
        assertEquals(OperationStatus.INVALID_INPUT, OperationScanner.classify(coercion, "x", 200))
        assertEquals(OperationStatus.ERROR, OperationScanner.classify("""{"errors":[{"message":"boom"}]}""", "x", 500))
    }
}
