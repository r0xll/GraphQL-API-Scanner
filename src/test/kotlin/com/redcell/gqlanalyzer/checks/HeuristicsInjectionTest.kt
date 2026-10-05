package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class HeuristicsInjectionTest {

    private val CLEAN = """{"data":{"item":{"__typename":"Item"}}}"""

    @Test
    fun `injectionSignatures recognises backend SQL and NoSQL errors`() {
        assertTrue(Heuristics.injectionSignatures("""ERROR: syntax error at or near "'"""").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures("MongoError: unknown operator \$where").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures("ORA-01756: quoted string not properly terminated").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures(CLEAN).isEmpty())
    }

    @Test
    fun `evaluatedExpression detects template evaluation (1337 = 7 times 191)`() {
        assertTrue(Heuristics.evaluatedExpression("""{"data":{"item":"1337 results"}}"""))
        assertFalse(Heuristics.evaluatedExpression(CLEAN))
    }

    @Test
    fun `fileReadSignatures detects passwd and win-ini markers`() {
        assertTrue(Heuristics.fileReadSignatures("""{"data":{"x":"root:x:0:0:root:/root:/bin/bash"}}""").isNotEmpty())
        assertTrue(Heuristics.fileReadSignatures("; for 16-bit app support\n[fonts]").isNotEmpty())
        assertTrue(Heuristics.fileReadSignatures(CLEAN).isEmpty())
    }

    @Test
    fun `timeBlindFired only when the latency jump clears the threshold`() {
        assertTrue(Heuristics.timeBlindFired(baselineMs = 120, payloadMs = 5200)) // ~5s sleep
        assertFalse(Heuristics.timeBlindFired(baselineMs = 120, payloadMs = 300)) // normal jitter
    }

    @Test
    fun `booleanBlindDiffers on a data-vs-empty or error differential`() {
        assertTrue(Heuristics.booleanBlindDiffers("""{"data":{"x":1}}""", """{"data":null}"""))
        assertTrue(Heuristics.booleanBlindDiffers("""{"data":{"x":1}}""", """{"errors":[{"message":"boom"}]}"""))
        assertFalse(Heuristics.booleanBlindDiffers("""{"data":{"x":1}}""", """{"data":{"x":1}}"""))
    }

    // ---- isInjectableScalar / injectionInsertionPoints broadening ----

    private fun ref(name: String, kind: String) = GqlTypeRef(kind = kind, name = name)
    private fun nn(name: String, kind: String) = GqlTypeRef(kind = "NON_NULL", ofType = ref(name, kind))

    /** Query { product(serial: ProductSerialNumber!, qty: Int!, note: String): Product } */
    private fun schema(): SchemaModel {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(
                GqlField(
                    "product", ref("Product", "OBJECT"),
                    args = listOf(
                        GqlInputValue("serial", nn("ProductSerialNumber", "SCALAR")),
                        GqlInputValue("qty", nn("Int", "SCALAR")),
                        GqlInputValue("note", ref("String", "SCALAR")),
                        GqlInputValue("category", ref("Category", "ENUM")),
                    ),
                ),
            ),
        )
        return SchemaModel(
            "Query", null, null,
            listOf(query, GqlType("Product", "OBJECT"), GqlType("ProductSerialNumber", "SCALAR"), GqlType("Category", "ENUM")),
        )
    }

    @Test
    fun `isInjectableScalar accepts string-backed scalars and rejects numeric, bool, enum, object`() {
        val s = schema()
        assertTrue(Heuristics.isInjectableScalar(s, nn("ProductSerialNumber", "SCALAR"))) // custom scalar
        assertTrue(Heuristics.isInjectableScalar(s, ref("String", "SCALAR")))
        assertTrue(Heuristics.isInjectableScalar(s, ref("ID", "SCALAR")))
        assertFalse(Heuristics.isInjectableScalar(s, nn("Int", "SCALAR")))
        assertFalse(Heuristics.isInjectableScalar(s, ref("Boolean", "SCALAR")))
        assertFalse(Heuristics.isInjectableScalar(s, ref("Category", "ENUM")))
        assertFalse(Heuristics.isInjectableScalar(s, ref("Product", "OBJECT")))
    }

    @Test
    fun `injectionInsertionPoints now includes custom-scalar args the old String-ID filter dropped`() {
        val points = Heuristics.injectionInsertionPoints(schema())
        val args = points.map { it.arg }.toSet()
        assertTrue("serial" in args)  // ProductSerialNumber! — would have been dropped by {String,ID}
        assertTrue("note" in args)    // plain String
        assertFalse("qty" in args)    // Int — not injectable
        assertFalse("category" in args) // enum — not injectable
    }
}
