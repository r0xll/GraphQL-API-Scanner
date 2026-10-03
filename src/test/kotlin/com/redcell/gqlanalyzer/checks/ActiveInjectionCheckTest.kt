package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.ActiveInjectionCheck
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ActiveInjectionCheckTest {

    private fun rsp(body: String) = MockContext.mockResponse(200, body)
    private fun nnString() = GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "SCALAR", name = "String"))

    /** Query { item(q: String!): Item }  (one query-root injection point) */
    private fun onePoint(): SchemaModel {
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(GqlField("item", GqlTypeRef(kind = "OBJECT", name = "Item"), args = listOf(GqlInputValue("q", nnString())))),
        )
        return SchemaModel("Query", null, null, listOf(query, GqlType("Item", "OBJECT")))
    }

    private val CLEAN = """{"data":{"item":{"__typename":"Item"}}}"""

    // ---- Heuristics ----

    @Test
    fun `injectionSignatures recognises backend SQL and NoSQL errors`() {
        assertTrue(Heuristics.injectionSignatures("""ERROR: syntax error at or near "'"""").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures("MongoError: unknown operator \$where").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures("ORA-01756: quoted string not properly terminated").isNotEmpty())
        assertTrue(Heuristics.injectionSignatures(CLEAN).isEmpty())
    }

    @Test
    fun `evaluatedExpression detects template evaluation`() {
        assertTrue(Heuristics.evaluatedExpression("""{"data":{"item":"49 results"}}"""))
        assertTrue(!Heuristics.evaluatedExpression(CLEAN))
    }

    // ---- Check behaviour ----

    @Test
    fun `error-based injection fires when the quote elicits a new SQL error`() {
        val s = onePoint()
        val sqlErr = """{"errors":[{"message":"ERROR: syntax error at or near \"'\""}]}"""
        // baseline (clean), quote (SQL error), ssti (clean)
        val (ctx, _) = MockContext.build(listOf(rsp(CLEAN), rsp(sqlErr), rsp(CLEAN)), schema = s)

        val findings = ActiveInjectionCheck().run(ctx)
        assertEquals(1, findings.count { it.checkId == "active-injection-error" })
        assertEquals("Query.item", findings.first { it.checkId == "active-injection-error" }.affectedOperation)
    }

    @Test
    fun `clean responses produce no finding`() {
        val s = onePoint()
        val (ctx, _) = MockContext.build(listOf(rsp(CLEAN)), schema = s) // last repeats
        assertTrue(ActiveInjectionCheck().run(ctx).isEmpty())
    }

    @Test
    fun `ssti fires when the arithmetic payload is evaluated`() {
        val s = onePoint()
        val evaluated = """{"data":{"item":"49"}}"""
        // baseline (clean, no 49), quote (clean), ssti (49)
        val (ctx, _) = MockContext.build(listOf(rsp(CLEAN), rsp(CLEAN), rsp(evaluated)), schema = s)

        val findings = ActiveInjectionCheck().run(ctx)
        assertEquals(1, findings.count { it.checkId == "active-injection-ssti" })
        assertTrue(findings.none { it.checkId == "active-injection-error" })
    }

    @Test
    fun `never injects into mutations — query-root gate`() {
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(GqlField("run", GqlTypeRef(kind = "SCALAR", name = "Boolean"), args = listOf(GqlInputValue("cmd", nnString())))),
        )
        val query = GqlType("Query", "OBJECT", fields = listOf(GqlField("ping", GqlTypeRef(kind = "SCALAR", name = "Boolean"))))
        val s = SchemaModel("Query", "Mutation", null, listOf(query, mutation))

        val (ctx, sent) = MockContext.build(listOf(rsp(CLEAN)), schema = s)
        val findings = ActiveInjectionCheck().run(ctx)

        assertTrue(findings.isEmpty())
        assertEquals(0, sent.requests.size) // the String arg lives on Mutation — never probed
    }

    @Test
    fun `point count is capped`() {
        val args = listOf("a", "b", "c").map { GqlField(it, GqlTypeRef(kind = "OBJECT", name = "Item"), args = listOf(GqlInputValue("x", nnString()))) }
        val s = SchemaModel("Query", null, null, listOf(GqlType("Query", "OBJECT", fields = args), GqlType("Item", "OBJECT")))

        val (ctx, sent) = MockContext.build(listOf(rsp(CLEAN)), schema = s)
        ActiveInjectionCheck(maxPoints = 2).run(ctx)

        // 2 points × 3 sends (baseline + quote + ssti) = 6; the third field is never touched.
        assertEquals(6, sent.requests.size)
        assertTrue(sent.bodies.none { it.contains("c(") })
    }
}
