package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.MockContext
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CheckEngineTest {

    private fun finding(name: String, location: String = "") =
        Finding(name, "d", Severity.LOW, Confidence.FIRM, "r", location = location)

    private class StubCheck(
        override val id: String,
        override val owaspId: String,
        val out: List<Finding>,
    ) : GraphQLCheck {
        override fun run(ctx: CheckContext) = out
    }

    @Test
    fun `stamps checkId owaspId and default location from request url`() {
        val (ctx, _) = MockContext.build(listOf(MockContext.mockResponse(200, "{}")))
        val engine = CheckEngine(listOf(StubCheck("c1", "API1:2023", listOf(finding("f")))))
        val out = engine.run(ctx)
        assertEquals(1, out.size)
        assertEquals("c1", out[0].checkId)
        assertEquals("API1:2023", out[0].owaspId)
        assertEquals("https://target.example/graphql", out[0].location)
    }

    @Test
    fun `dedupes by checkId and location`() {
        val (ctx, _) = MockContext.build(listOf(MockContext.mockResponse(200, "{}")))
        val dupes = listOf(finding("a", "loc1"), finding("b", "loc1"), finding("c", "loc2"))
        val out = CheckEngine(listOf(StubCheck("c1", "API1:2023", dupes))).run(ctx)
        // (c1,loc1) collapses to one; (c1,loc2) survives.
        assertEquals(2, out.size)
        assertEquals(setOf("loc1", "loc2"), out.map { it.location }.toSet())
    }

    @Test
    fun `isolates a throwing check without failing the run`() {
        val (ctx, _) = MockContext.build(listOf(MockContext.mockResponse(200, "{}")))
        val boom = object : GraphQLCheck {
            override val id = "boom"; override val owaspId = "API0:2023"
            override fun run(ctx: CheckContext): List<Finding> = throw IllegalStateException("kaboom")
        }
        val good = StubCheck("good", "API2:2023", listOf(finding("ok")))
        val out = CheckEngine(listOf(boom, good)).run(ctx)
        assertEquals(1, out.size)
        assertTrue(out[0].checkId == "good")
    }
}
