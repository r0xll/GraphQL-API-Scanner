package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.ContentTypeBypassCheck
import com.redcell.gqlanalyzer.checks.impl.DirectiveOverloadCheck
import com.redcell.gqlanalyzer.checks.impl.GraphiqlExposedCheck
import com.redcell.gqlanalyzer.checks.impl.SsrfSeederCheck
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase5ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)

    // ---- SsrfSeederCheck (API7, static) ----

    private fun schemaWithUrlArg(): SchemaModel {
        val str = GqlTypeRef(kind = "SCALAR", name = "String")
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(
                GqlField("fetchImage", str, args = listOf(GqlInputValue("url", str))),
                GqlField("search", str, args = listOf(GqlInputValue("term", str))),
            ),
        )
        return SchemaModel("Query", null, null, listOf(query))
    }

    @Test
    fun `ssrf seeder flags url-like args and sends nothing`() {
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = schemaWithUrlArg())
        val check = SsrfSeederCheck()
        val f = check.run(ctx)
        assertEquals(1, f.size)
        assertEquals("API7:2023", check.owaspId)
        assertTrue(f[0].detail.contains("fetchImage"))
        assertTrue(!f[0].detail.contains("search")) // 'term' is not a URL-like arg
        assertTrue(sent.requests.isEmpty())
    }

    @Test
    fun `ssrf seeder silent without url-like args`() {
        val str = GqlTypeRef(kind = "SCALAR", name = "String")
        val schema = SchemaModel(
            "Query", null, null,
            listOf(GqlType("Query", "OBJECT", fields = listOf(GqlField("search", str, args = listOf(GqlInputValue("term", str)))))),
        )
        val (ctx, _) = MockContext.build(listOf(rsp(200, "{}")), schema = schema)
        assertTrue(SsrfSeederCheck().run(ctx).isEmpty())
    }

    // ---- GraphiqlExposedCheck (API8) ----

    @Test
    fun `graphiql detector matches ide html and rejects plain json`() {
        assertTrue(Heuristics.isGraphqlIdeHtml("<html><title>GraphiQL</title><body>...</body></html>"))
        assertTrue(Heuristics.isGraphqlIdeHtml("<div id=root></div><script>GraphQLPlayground.init()</script>"))
        assertTrue(!Heuristics.isGraphqlIdeHtml("""{"data":{"__typename":"Query"}}"""))
    }

    @Test
    fun `graphiql check fires when ide served`() {
        val html = "<html><head><title>GraphiQL</title></head><body></body></html>"
        val (ctx, _) = MockContext.build(listOf(rsp(200, html)))
        assertEquals(1, GraphiqlExposedCheck().run(ctx).size)
    }

    @Test
    fun `graphiql check silent on json endpoint`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        assertTrue(GraphiqlExposedCheck().run(ctx).isEmpty())
    }

    // ---- ContentTypeBypassCheck (API8) ----

    @Test
    fun `content-type bypass fires when text-plain executes`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        assertEquals(1, ContentTypeBypassCheck().run(ctx).size)
    }

    @Test
    fun `content-type bypass silent when rejected`() {
        val (ctx, _) = MockContext.build(listOf(rsp(400, """{"errors":[{"message":"invalid content type"}]}""")))
        assertTrue(ContentTypeBypassCheck().run(ctx).isEmpty())
    }

    // ---- DirectiveOverloadCheck (API4) ----

    @Test
    fun `directive overload fires when accepted and is capped at 10`() {
        val (ctx, sent) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        val f = DirectiveOverloadCheck().run(ctx)
        assertEquals(1, f.size)
        val directiveCount = Regex("@skip").findAll(sent.bodies.first()).count()
        assertEquals(DirectiveOverloadCheck.PROOF_CAP, directiveCount)
        assertTrue(directiveCount <= 10)
    }

    @Test
    fun `directive overload silent when rejected`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"errors":[{"message":"Directive @skip can only be used once"}]}""")))
        assertTrue(DirectiveOverloadCheck().run(ctx).isEmpty())
    }
}
