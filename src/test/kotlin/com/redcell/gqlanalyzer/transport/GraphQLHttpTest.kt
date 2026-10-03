package com.redcell.gqlanalyzer.transport

import burp.api.montoya.http.message.requests.HttpRequest
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlin.test.Test

class GraphQLHttpTest {

    @Test
    fun `buildJsonRequest sets POST, json content-type, body and extra headers without sending`() {
        val base = mockk<HttpRequest>()
        every { base.withMethod("POST") } returns base
        every { base.withBody(any<String>()) } returns base
        every { base.withUpdatedHeader(any(), any()) } returns base

        val body = """{"query":"query { me { id } }"}"""
        val out = GraphQLHttp.buildJsonRequest(base, body, mapOf("Authorization" to "Bearer t"))

        verify { base.withMethod("POST") }
        verify { base.withBody(body) }
        verify { base.withUpdatedHeader("Content-Type", "application/json") }
        verify { base.withUpdatedHeader("Authorization", "Bearer t") }
        // No MontoyaApi/Http is involved — the helper only composes, never sends.
        assert(out === base)
    }
}
