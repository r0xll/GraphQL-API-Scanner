package com.redcell.gqlanalyzer.checks

import burp.api.montoya.websocket.WebSockets
import burp.api.montoya.websocket.extension.ExtensionWebSocket
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreation
import burp.api.montoya.websocket.extension.ExtensionWebSocketCreationStatus
import com.redcell.gqlanalyzer.checks.impl.CswshCheck
import com.redcell.gqlanalyzer.checks.impl.SensitiveFlowCheck
import com.redcell.gqlanalyzer.checks.impl.UserEnumerationCheck
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import io.mockk.every
import io.mockk.mockk
import java.util.Optional
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase10ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)
    private val str = GqlTypeRef(kind = "SCALAR", name = "String")

    // ---- SensitiveFlowCheck (API6, static) ----

    private fun schemaWithFlows(): SchemaModel {
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(
                GqlField("refundOrder", str, args = listOf(GqlInputValue("orderId", str))),
                GqlField("updateProfile", str),
            ),
        )
        return SchemaModel("Query", "Mutation", null, listOf(GqlType("Query", "OBJECT"), mutation))
    }

    @Test
    fun `sensitive flow flags high-value mutations and sends nothing`() {
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = schemaWithFlows())
        val f = SensitiveFlowCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].detail.contains("refundOrder"))
        assertTrue(!f[0].detail.contains("updateProfile"))
        assertTrue(sent.requests.isEmpty())
    }

    @Test
    fun `sensitive flow silent on benign schema`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, "{}")), schema = SchemaFixtures.benign())
        assertTrue(SensitiveFlowCheck().run(ctx).isEmpty())
    }

    // ---- UserEnumerationCheck (API2) ----

    @Test
    fun `reveals predicate on differing vs identical error templates`() {
        val valid = """{"errors":[{"message":"Incorrect password for alice"}]}"""
        val invalid = """{"errors":[{"message":"No account for bob"}]}"""
        assertTrue(UserEnumerationCheck.reveals(valid, invalid, "alice", "bob"))
        // Same template once identifiers are stripped -> not revealing.
        val vGeneric = """{"errors":[{"message":"Invalid credentials for alice"}]}"""
        val iGeneric = """{"errors":[{"message":"Invalid credentials for bob"}]}"""
        assertTrue(!UserEnumerationCheck.reveals(vGeneric, iGeneric, "alice", "bob"))
    }

    private fun loginSchema(): SchemaModel {
        val mutation = GqlType(
            "Mutation", "OBJECT",
            fields = listOf(
                GqlField(
                    "login", str,
                    args = listOf(
                        GqlInputValue("username", GqlTypeRef(kind = "NON_NULL", ofType = str)),
                        GqlInputValue("password", GqlTypeRef(kind = "NON_NULL", ofType = str)),
                    ),
                ),
            ),
        )
        return SchemaModel("Query", "Mutation", null, listOf(GqlType("Query", "OBJECT"), mutation))
    }

    @Test
    fun `user enumeration fires on differential and is skipped without config`() {
        val cfg = CheckConfig(userEnumValid = "alice", userEnumInvalid = "nobody")
        val responses = listOf(
            rsp(200, """{"errors":[{"message":"Incorrect password"}]}"""),   // valid user
            rsp(200, """{"errors":[{"message":"No such account"}]}"""),       // invalid user
        )
        val (ctx, sent) = MockContext.build(responses, config = cfg, schema = loginSchema())
        val f = UserEnumerationCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(2, sent.requests.size)

        val (ctxNoCfg, sent2) = MockContext.build(responses, schema = loginSchema())
        assertTrue(UserEnumerationCheck().run(ctxNoCfg).isEmpty())
        assertTrue(sent2.requests.isEmpty()) // gated: no probes without config
    }

    // ---- CswshCheck (API8) ----

    private fun subSchema() = SchemaModel("Query", null, "Subscription", listOf(GqlType("Query", "OBJECT"), GqlType("Subscription", "OBJECT")))

    private fun stubWebSockets(ctx: com.redcell.gqlanalyzer.model.CheckContext, status: ExtensionWebSocketCreationStatus) {
        val creation = mockk<ExtensionWebSocketCreation>()
        every { creation.status() } returns status
        every { creation.webSocket() } returns Optional.empty<ExtensionWebSocket>()
        val ws = mockk<WebSockets>()
        every { ws.createWebSocket(any<burp.api.montoya.http.message.requests.HttpRequest>()) } returns creation
        every { ctx.api.websockets() } returns ws
    }

    @Test
    fun `cswsh fires when cross-origin handshake succeeds`() {
        val (ctx, _) = MockContext.build(listOf(rsp(101, "")), schema = subSchema())
        stubWebSockets(ctx, ExtensionWebSocketCreationStatus.SUCCESS)
        assertEquals(1, CswshCheck().run(ctx).size)
    }

    @Test
    fun `cswsh silent when handshake rejected`() {
        val (ctx, _) = MockContext.build(listOf(rsp(101, "")), schema = subSchema())
        stubWebSockets(ctx, ExtensionWebSocketCreationStatus.NON_UPGRADE_RESPONSE)
        assertTrue(CswshCheck().run(ctx).isEmpty())
    }

    @Test
    fun `cswsh skipped without a subscription type`() {
        val (ctx, _) = MockContext.build(listOf(rsp(101, "")), schema = SchemaFixtures.benign())
        assertTrue(CswshCheck().run(ctx).isEmpty())
    }
}
