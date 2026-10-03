package com.redcell.gqlanalyzer.checks

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.responses.HttpResponse
import com.redcell.gqlanalyzer.checks.impl.AuthAmplificationCheck
import com.redcell.gqlanalyzer.checks.impl.CorsCheck
import com.redcell.gqlanalyzer.checks.impl.IdorEnumerationCheck
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase9ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)

    // ---- Heuristics.corsMisconfig + CorsCheck (API8) ----

    @Test
    fun `cors misconfig predicate`() {
        assertTrue(Heuristics.corsMisconfig("https://evil.example", "true", "https://evil.example"))
        assertTrue(Heuristics.corsMisconfig("*", "true", "https://evil.example"))
        assertTrue(!Heuristics.corsMisconfig("https://evil.example", "false", "https://evil.example"))
        assertTrue(!Heuristics.corsMisconfig(null, "true", "https://evil.example"))
    }

    private fun corsResponse(acao: String?, acac: String?): HttpRequestResponse {
        val resp = mockk<HttpResponse>()
        every { resp.statusCode() } returns 200
        every { resp.bodyToString() } returns """{"data":{"__typename":"Query"}}"""
        every { resp.headerValue("Access-Control-Allow-Origin") } returns acao
        every { resp.headerValue("Access-Control-Allow-Credentials") } returns acac
        val rr = mockk<HttpRequestResponse>()
        every { rr.response() } returns resp
        every { rr.request() } returns mockk(relaxed = true)
        return rr
    }

    @Test
    fun `cors check fires on reflected origin with credentials`() {
        val (ctx, _) = MockContext.build(listOf(corsResponse("https://evil.example", "true")))
        assertEquals(1, CorsCheck().run(ctx).size)
    }

    @Test
    fun `cors check silent without credentials`() {
        val (ctx, _) = MockContext.build(listOf(corsResponse("https://evil.example", null)))
        assertTrue(CorsCheck().run(ctx).isEmpty())
    }

    // ---- IdorEnumerationCheck (API1) ----

    private fun idSchema(): SchemaModel {
        val user = GqlTypeRef(kind = "OBJECT", name = "User")
        val idNN = GqlTypeRef(kind = "NON_NULL", ofType = GqlTypeRef(kind = "SCALAR", name = "ID"))
        val query = GqlType(
            "Query", "OBJECT",
            fields = listOf(GqlField("user", user, args = listOf(GqlInputValue("id", idNN)))),
        )
        return SchemaModel("Query", null, null, listOf(query, GqlType("User", "OBJECT")))
    }

    @Test
    fun `idor fires when adjacent ids return distinct objects`() {
        val (ctx, sent) = MockContext.build(
            listOf(rsp(200, """{"data":{"user":{"id":"1"}}}"""), rsp(200, """{"data":{"user":{"id":"2"}}}""")),
            schema = idSchema(),
        )
        val f = IdorEnumerationCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(2, sent.requests.size)
    }

    @Test
    fun `idor silent when second id is null`() {
        val (ctx, _) = MockContext.build(
            listOf(rsp(200, """{"data":{"user":{"id":"1"}}}"""), rsp(200, """{"data":{"user":null}}""")),
            schema = idSchema(),
        )
        assertTrue(IdorEnumerationCheck().run(ctx).isEmpty())
    }

    @Test
    fun `idPair uses numeric known id`() {
        assertEquals("41" to "42", IdorEnumerationCheck.idPair("41"))
        assertEquals("1" to "2", IdorEnumerationCheck.idPair(null))
        assertEquals("1" to "2", IdorEnumerationCheck.idPair("abc"))
    }

    // ---- AuthAmplificationCheck (API2, static) ----

    @Test
    fun `auth amplification flags auth mutations statically`() {
        val str = GqlTypeRef(kind = "SCALAR", name = "String")
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(
                GqlField("login", str, args = listOf(GqlInputValue("username", str), GqlInputValue("password", str))),
            ),
        )
        val schema = SchemaModel("Query", "Mutation", null, listOf(GqlType("Query", "OBJECT"), mutation))
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = schema)
        val f = AuthAmplificationCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].detail.contains("login"))
        assertTrue(sent.requests.isEmpty()) // schema-static
    }

    @Test
    fun `auth amplification silent without auth fields`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, "{}")), schema = SchemaFixtures.benign())
        assertTrue(AuthAmplificationCheck().run(ctx).isEmpty())
    }
}
