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
}
