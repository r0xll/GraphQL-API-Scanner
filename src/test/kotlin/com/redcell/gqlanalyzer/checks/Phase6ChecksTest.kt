package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.AltIntrospectionCheck
import com.redcell.gqlanalyzer.checks.impl.ApqDetectionCheck
import com.redcell.gqlanalyzer.checks.impl.DeferStreamCheck
import com.redcell.gqlanalyzer.checks.impl.DeprecatedFieldInventoryCheck
import com.redcell.gqlanalyzer.checks.impl.EngineFingerprintCheck
import com.redcell.gqlanalyzer.checks.impl.TracingExtensionsCheck
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase6ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)

    // ---- EngineFingerprints / EngineFingerprintCheck (API9) ----

    @Test
    fun `fingerprint table identifies engines from error text`() {
        assertEquals("graphql-java", EngineFingerprints.identify(listOf("Validation error of type FieldUndefined: ...")))
        assertEquals("Ruby graphql / graphql-ruby", EngineFingerprints.identify(listOf("Field 'x' doesn't exist on type 'Query'")))
        assertTrue(EngineFingerprints.identify(listOf("totally generic error")) == null)
    }

    @Test
    fun `engine fingerprint check fires with identified engine`() {
        // 4 probes -> replay the java validation error for all.
        val err = """{"errors":[{"message":"Validation error of type FieldUndefined"}]}"""
        val (ctx, _) = MockContext.build(listOf(rsp(200, err)))
        val f = EngineFingerprintCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].name.contains("graphql-java"))
    }

    // ---- AltIntrospectionCheck (API9) ----

    @Test
    fun `alt introspection silent when standard POST works`() {
        val schemaBody = """{"data":{"__schema":{"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":{"kind":"OBJECT","name":"User"}}]}]}}}"""
        val (ctx, _) = MockContext.build(listOf(rsp(200, schemaBody)))
        assertTrue(AltIntrospectionCheck().run(ctx).isEmpty())
    }

    @Test
    fun `alt introspection fires when POST blocked but GET leaks`() {
        val blocked = """{"errors":[{"message":"introspection is disabled"}]}"""
        val schemaBody = """{"data":{"__schema":{"types":[{"kind":"OBJECT","name":"Query","fields":[{"name":"me","args":[],"type":{"kind":"OBJECT","name":"User"}}]}]}}}"""
        // send order: POST __schema (blocked), GET (leaks), text/plain (blocked), __type (blocked)
        val (ctx, _) = MockContext.build(
            listOf(rsp(200, blocked), rsp(200, schemaBody), rsp(200, blocked), rsp(200, blocked)),
        )
        val f = AltIntrospectionCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].name.contains("GET"))
    }

    @Test
    fun `typeProbeLeaks detects __type fields`() {
        assertTrue(AltIntrospectionCheck.typeProbeLeaks("""{"data":{"__type":{"name":"Query","fields":[{"name":"me"}]}}}"""))
        assertTrue(!AltIntrospectionCheck.typeProbeLeaks("""{"data":{"__type":null}}"""))
    }

    // ---- ApqDetectionCheck ----

    @Test
    fun `apq detected on PersistedQueryNotFound`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"errors":[{"message":"PersistedQueryNotFound"}]}""")))
        assertEquals(1, ApqDetectionCheck().run(ctx).size)
    }

    @Test
    fun `apq silent otherwise`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"errors":[{"message":"Must provide query string"}]}""")))
        assertTrue(ApqDetectionCheck().run(ctx).isEmpty())
    }

    // ---- TracingExtensionsCheck (API8) ----

    @Test
    fun `tracing extensions detected`() {
        val body = """{"data":{"__typename":"Query"},"extensions":{"tracing":{"version":1}}}"""
        val (ctx, _) = MockContext.build(listOf(rsp(200, body)))
        assertEquals(1, TracingExtensionsCheck().run(ctx).size)
    }

    @Test
    fun `no tracing extensions - silent`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, """{"data":{"__typename":"Query"}}""")))
        assertTrue(TracingExtensionsCheck().run(ctx).isEmpty())
    }

    // ---- DeferStreamCheck ----

    @Test
    fun `defer supported detection`() {
        assertTrue(DeferStreamCheck.deferSupported("""{"data":{"__typename":"Query"}}"""))
        assertTrue(DeferStreamCheck.deferSupported("""{"hasNext":true,"incremental":[]}"""))
        assertTrue(!DeferStreamCheck.deferSupported("""{"errors":[{"message":"Unknown directive @defer"}]}"""))
    }

    // ---- DeprecatedFieldInventoryCheck (API9, static) ----

    @Test
    fun `deprecated inventory lists deprecated fields`() {
        val user = GqlType(
            "User", "OBJECT",
            fields = listOf(
                GqlField("id", GqlTypeRef(kind = "SCALAR", name = "ID")),
                GqlField("legacyName", GqlTypeRef(kind = "SCALAR", name = "String"), isDeprecated = true, deprecationReason = "use name"),
            ),
        )
        val schema = SchemaModel("Query", null, null, listOf(user))
        val (ctx, sent) = MockContext.build(listOf(rsp(200, "{}")), schema = schema)
        val f = DeprecatedFieldInventoryCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].detail.contains("User.legacyName"))
        assertTrue(sent.requests.isEmpty()) // schema-static
    }

    @Test
    fun `deprecated inventory silent when none deprecated`() {
        val (ctx, _) = MockContext.build(listOf(rsp(200, "{}")), schema = SchemaFixtures.benign())
        assertTrue(DeprecatedFieldInventoryCheck().run(ctx).isEmpty())
    }
}
