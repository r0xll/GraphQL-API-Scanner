package com.redcell.gqlanalyzer.checks

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.Http
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.CheckContext
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot

/** Test scaffolding: a CheckContext whose sendRequest replays scripted responses. */
object MockContext {

    class Sent {
        val requests = mutableListOf<HttpRequest>()
        val bodies = mutableListOf<String>()
    }

    fun mockResponse(status: Int, body: String): HttpRequestResponse {
        val resp = mockk<HttpResponse>()
        every { resp.statusCode() } returns status.toShort()
        every { resp.bodyToString() } returns body
        val rr = mockk<HttpRequestResponse>()
        every { rr.response() } returns resp
        every { rr.request() } returns mockk(relaxed = true)
        return rr
    }

    /**
     * @param responses replayed in order; the last repeats if more sends occur.
     * @return the context and a [Sent] record capturing each request body sent.
     */
    fun build(
        responses: List<HttpRequestResponse>,
        config: CheckConfig = CheckConfig(),
    ): Pair<CheckContext, Sent> {
        val sent = Sent()
        val base = mockk<HttpRequest>()
        val bodySlot = slot<String>()
        every { base.withMethod(any()) } returns base
        every { base.withPath(any()) } returns base
        every { base.withUpdatedHeader(any(), any()) } returns base
        every { base.withBody(capture(bodySlot)) } answers {
            sent.bodies.add(bodySlot.captured)
            base
        }
        every { base.path() } returns "/graphql"
        every { base.url() } returns "https://target.example/graphql"

        val http = mockk<Http>()
        var i = 0
        every { http.sendRequest(any<HttpRequest>()) } answers {
            sent.requests.add(firstArg())
            responses[i.coerceAtMost(responses.size - 1)].also { i++ }
        }

        val api = mockk<MontoyaApi>()
        every { api.http() } returns http
        every { api.logging() } returns mockk(relaxed = true)

        return CheckContext(api, base, schema = null, config = config) to sent
    }
}
