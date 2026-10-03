package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.CircularFragmentCheck
import com.redcell.gqlanalyzer.checks.impl.FieldDuplicationCheck
import com.redcell.gqlanalyzer.checks.impl.PaginationAbuseCheck
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase7ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)

    // ---- CircularFragmentCheck (API4) ----

    @Test
    fun `circular fragment fires when executed instead of cycle-rejected`() {
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        val f = CircularFragmentCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(sent.bodies.first().contains("...SelfRef"))
    }

    @Test
    fun `circular fragment silent when server rejects the cycle`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"errors":[{"message":"Cannot spread fragment \"SelfRef\" within itself."}]}""")))
        assertTrue(CircularFragmentCheck().run(ctx).isEmpty())
    }

    @Test
    fun `missingCycleDetection predicate`() {
        assertTrue(CircularFragmentCheck.missingCycleDetection("""{"data":{"__typename":"Query"}}"""))
        assertTrue(!CircularFragmentCheck.missingCycleDetection("""{"errors":[{"message":"detected a fragment cycle"}]}"""))
    }

    // ---- PaginationAbuseCheck (API4) ----

    private fun schemaWithPagination(): SchemaModel {
        val user = GqlTypeRef(kind = "OBJECT", name = "User")
        val intt = GqlTypeRef(kind = "SCALAR", name = "Int")
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(
                GqlField("users", user, args = listOf(GqlInputValue("first", intt))),
                GqlField("me", user),
            ),
        )
        return SchemaModel("Query", null, null, listOf(query, GqlType("User", "OBJECT")))
    }

    @Test
    fun `pagination abuse fires when large page accepted`() {
        val (ctx, sent) = MockContext.build(
            listOf(rsp(200, """{"data":{"users":{"__typename":"User"}}}""")),
            schema = schemaWithPagination(),
        )
        val f = PaginationAbuseCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(sent.bodies.first().contains("first: ${PaginationAbuseCheck.LARGE}"))
    }

    @Test
    fun `pagination abuse silent when server caps with a limit error`() {
        val (ctx, _) = MockContext.build(
            listOf(rsp(200, """{"errors":[{"message":"first must be at most 100"}]}""")),
            schema = schemaWithPagination(),
        )
        assertTrue(PaginationAbuseCheck().run(ctx).isEmpty())
    }

    @Test
    fun `pagination abuse silent without a pagination arg`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, "{}")), schema = SchemaFixtures.benign())
        assertTrue(PaginationAbuseCheck().run(ctx).isEmpty())
    }

    // ---- FieldDuplicationCheck (API4) ----

    @Test
    fun `field duplication fires when accepted and is capped at 10`() {
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        val f = FieldDuplicationCheck().run(ctx)
        assertEquals(1, f.size)
        val count = Regex("__typename").findAll(sent.bodies.first()).count()
        assertEquals(FieldDuplicationCheck.PROOF_CAP, count)
    }

    @Test
    fun `field duplication silent when rejected`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"errors":[{"message":"boom"}]}""")))
        assertTrue(FieldDuplicationCheck().run(ctx).isEmpty())
    }
}
