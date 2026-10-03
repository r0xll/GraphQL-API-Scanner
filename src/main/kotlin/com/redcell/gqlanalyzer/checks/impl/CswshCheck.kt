package com.redcell.gqlanalyzer.checks.impl

import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * API8:2023 — Cross-Site WebSocket Hijacking (CSWSH) on GraphQL subscriptions. Opens
 * the WebSocket upgrade with a foreign `Origin`; if the handshake completes anyway the
 * server does not validate Origin, so a malicious page can open an authenticated
 * subscription in a victim's browser (cookie auth). Gated on the schema advertising a
 * subscription type. One socket, no messages — closed immediately; non-destructive.
 */
class CswshCheck : GraphQLCheck {
    override val id = "cswsh"
    override val owaspId = "API8:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        if (schema.subscriptionTypeName == null) return emptyList()

        val path = ctx.request.path().substringBefore('?')
        val wsReq = ctx.request.withMethod("GET").withPath(path).withBody("")
            .withUpdatedHeader("Upgrade", "websocket")
            .withUpdatedHeader("Connection", "Upgrade")
            .withUpdatedHeader("Sec-WebSocket-Version", "13")
            .withUpdatedHeader("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .withUpdatedHeader("Sec-WebSocket-Protocol", "graphql-transport-ws, graphql-ws")
            .withUpdatedHeader("Origin", TEST_ORIGIN)

        val creation = ctx.api.websockets().createWebSocket(wsReq)
        creation.webSocket().ifPresent { it.close() }
        if (creation.status() != ExtensionWebSocketCreationStatus.SUCCESS) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL subscription CSWSH (cross-origin WebSocket handshake accepted)",
                detail = """
                    The subscription WebSocket completed its upgrade handshake even with a foreign
                    `Origin: $TEST_ORIGIN`. The server does not validate the Origin of WebSocket
                    connections, so if sessions are cookie-based a malicious site can open an
                    authenticated subscription in a logged-in victim's browser and read streamed data
                    (Cross-Site WebSocket Hijacking).

                    One socket was opened with a spoofed Origin and closed immediately; no messages
                    were exchanged. Confirm the session is cookie/ambient-credential based (token-in-
                    header auth is not exploitable this way).

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N (6.5, Medium) — victim interaction
                    required; confidentiality impact scales with what the subscription streams.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Validate the `Origin` header on the WebSocket upgrade against an allow-list and
                    reject unknown origins, require a CSRF/handshake token for subscription
                    connections, and prefer non-cookie (bearer) auth for the WebSocket transport.
                """.trimIndent(),
            ),
        )
    }

    companion object {
        const val TEST_ORIGIN = "https://evil.example"
    }
}
