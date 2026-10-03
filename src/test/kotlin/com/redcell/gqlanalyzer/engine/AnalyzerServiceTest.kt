package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.IntrospectionRunner
import com.redcell.gqlanalyzer.schema.SchemaModel
import io.mockk.every
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AnalyzerServiceTest {

    private class StubCheck : GraphQLCheck {
        override val id = "stub"
        override val owaspId = "API1:2023"
        var seenSchema: SchemaModel? = null
        override fun run(ctx: CheckContext): List<Finding> {
            seenSchema = ctx.schema
            return listOf(Finding("stub finding", "d", Severity.LOW, Confidence.FIRM, "r"))
        }
    }

    @Test
    fun `analyze wires introspected schema into the context and returns findings`() {
        val schema = SchemaModel("Query", null, null, emptyList())
        val intro = mockk<IntrospectionRunner>()
        every { intro.run(any()) } returns IntrospectionRunner.Result(schema, introspectionEnabled = true)

        val stub = StubCheck()
        val api = mockk<MontoyaApi>(relaxed = true)
        val base = mockk<HttpRequest>()
        every { base.url() } returns "https://target.example/graphql"

        val svc = AnalyzerService(api, CheckEngine(listOf(stub)), intro)
        val result = svc.analyze(base, CheckConfig())

        assertTrue(result.introspectionEnabled)
        assertSame(schema, result.schema)
        assertSame(schema, stub.seenSchema) // schema was passed into the check context
        assertEquals(1, result.findings.size)
        assertEquals("stub", result.findings[0].checkId)
        assertEquals("https://target.example/graphql", result.findings[0].location)
    }

    @Test
    fun `rerunOperation sends the edited request and rescores the operation`() {
        val schema = com.redcell.gqlanalyzer.checks.SchemaFixtures.full()
        val op = OperationEnumerator.enumerate(schema).first { it.name == "QUERY.adminUsers" }
        val body = """{"data":{"adminUsers":{"__typename":"User"}}}"""

        val resp = mockk<burp.api.montoya.http.message.responses.HttpResponse>()
        every { resp.statusCode() } returns 200
        every { resp.bodyToString() } returns body
        val rr = mockk<burp.api.montoya.http.message.HttpRequestResponse>()
        every { rr.response() } returns resp

        val edited = mockk<HttpRequest>()
        every { edited.url() } returns "https://target.example/graphql"

        val http = mockk<burp.api.montoya.http.Http>()
        every { http.sendRequest(edited) } returns rr
        val api = mockk<MontoyaApi>(relaxed = true)
        every { api.http() } returns http

        val svc = AnalyzerService(api, CheckEngine(emptyList()), mockk())
        val result = svc.rerunOperation(edited, CheckConfig(), schema, op)

        io.mockk.verify(exactly = 1) { http.sendRequest(edited) } // sent verbatim, once
        assertEquals(com.redcell.gqlanalyzer.model.OperationStatus.RESOLVED, result.status)
        assertTrue(result.findings.any { it.checkId == "op-bfla" })
        assertSame(rr, result.requestResponse)
    }

    @Test
    fun `enumerateWithProvidedSchema uses the given schema and runs endpoint checks without introspecting`() {
        val provided = com.redcell.gqlanalyzer.checks.SchemaFixtures.full()
        val intro = mockk<IntrospectionRunner>() // must NOT be called
        val stub = StubCheck()
        val api = mockk<MontoyaApi>(relaxed = true)
        val base = mockk<HttpRequest>()
        every { base.url() } returns "https://target.example/graphql"

        val svc = AnalyzerService(api, CheckEngine(listOf(stub)), intro)
        val result = svc.enumerateWithProvidedSchema(base, CheckConfig(), provided)

        assertSame(provided, result.schema)
        assertSame(provided, stub.seenSchema) // provided schema reached the check context
        assertTrue(result.operations.isNotEmpty()) // operations enumerated from the provided schema
        assertEquals(1, result.endpointFindings.size)
        io.mockk.verify(exactly = 0) { intro.run(any()) } // no introspection request
    }
}
