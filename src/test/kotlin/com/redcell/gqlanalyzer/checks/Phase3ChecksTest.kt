package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.BflaCheck
import com.redcell.gqlanalyzer.checks.impl.BolaCheck
import com.redcell.gqlanalyzer.checks.impl.DepthComplexityCheck
import com.redcell.gqlanalyzer.checks.impl.FieldAuthzCheck
import com.redcell.gqlanalyzer.checks.impl.FieldSuggestionCheck
import com.redcell.gqlanalyzer.checks.impl.InjectionSeederCheck
import com.redcell.gqlanalyzer.checks.impl.MassAssignmentCheck
import com.redcell.gqlanalyzer.checks.impl.VerboseErrorCheck
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.Severity
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class Phase3ChecksTest {

    private fun rsp(status: Int, body: String) = MockContext.mockResponse(status, body)
    private fun ok(body: String) = listOf(rsp(200, body))

    // ---- FieldSuggestionCheck (API9) ----
    @Test
    fun `field suggestions fire on did-you-mean leakage`() {
        val body = """{"data":null,"errors":[{"message":"Cannot query field \"x\" on type \"Query\". Did you mean \"user\" or \"me\"?"}]}"""
        val (ctx, _) = MockContext.build(ok(body))
        val f = FieldSuggestionCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].detail.contains("user"))
    }

    @Test
    fun `field suggestions silent when no suggestion`() {
        val (ctx, _) = MockContext.build(ok("""{"errors":[{"message":"Syntax Error"}]}"""))
        assertTrue(FieldSuggestionCheck().run(ctx).isEmpty())
    }

    // ---- VerboseErrorCheck (API8) ----
    @Test
    fun `verbose errors fire on stack trace leakage`() {
        val body = """{"errors":[{"message":"NullPointerException","extensions":{"exception":{"stacktrace":["at com.app.Resolver.get(Resolver.java:42)"]}}}]}"""
        val (ctx, _) = MockContext.build(ok(body))
        assertEquals(1, VerboseErrorCheck().run(ctx).size)
    }

    @Test
    fun `verbose errors silent on clean generic error`() {
        val (ctx, _) = MockContext.build(ok("""{"errors":[{"message":"Something went wrong"}]}"""))
        assertTrue(VerboseErrorCheck().run(ctx).isEmpty())
    }

    // ---- MassAssignmentCheck (API3, static) ----
    @Test
    fun `mass assignment fires on privileged input fields and lists mutation`() {
        val (ctx, _) = MockContext.build(ok("{}"), schema = SchemaFixtures.full())
        val f = MassAssignmentCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(Severity.HIGH, f[0].severity)
        assertTrue(f[0].detail.contains("UpdateUserInput.role"))
        assertTrue(f[0].detail.contains("updateUser"))
    }

    @Test
    fun `mass assignment silent on benign schema`() {
        val (ctx, _) = MockContext.build(ok("{}"), schema = SchemaFixtures.benign())
        assertTrue(MassAssignmentCheck().run(ctx).isEmpty())
    }

    // ---- InjectionSeederCheck (static) ----
    @Test
    fun `injection seeder enumerates string-ID insertion points, sends nothing`() {
        val (ctx, sent) = MockContext.build(ok("{}"), schema = SchemaFixtures.full())
        val f = InjectionSeederCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(Severity.INFORMATION, f[0].severity)
        assertTrue(f[0].detail.contains("sqlmap"))
        assertTrue(sent.requests.isEmpty()) // schema-static: no probing
    }

    // ---- BolaCheck (API1) ----
    @Test
    fun `bola skipped without two identities`() {
        val (ctx, _) = MockContext.build(ok("{}"), schema = SchemaFixtures.full())
        assertTrue(BolaCheck().run(ctx).isEmpty())
    }

    @Test
    fun `bola FIRM when identity B reads A-owned object (known id)`() {
        val v = BolaCheck.decide(
            aBody = """{"data":{"user":{"__typename":"User"}}}""",
            bBody = """{"data":{"user":{"__typename":"User"}}}""",
            field = "user",
            knownOwnership = true,
        )!!
        assertEquals(com.redcell.gqlanalyzer.model.Confidence.FIRM, v.confidence)
    }

    @Test
    fun `bola TENTATIVE when both identities get identical object (unknown ownership)`() {
        val same = """{"data":{"user":{"id":"1","email":"a@b.c"}}}"""
        val v = BolaCheck.decide(same, same, "user", knownOwnership = false)!!
        assertEquals(com.redcell.gqlanalyzer.model.Confidence.TENTATIVE, v.confidence)
    }

    @Test
    fun `bola no verdict when B denied`() {
        val a = """{"data":{"user":{"id":"1"}}}"""
        val bDenied = """{"data":null,"errors":[{"message":"forbidden"}]}"""
        assertTrue(BolaCheck.decide(a, bDenied, "user", knownOwnership = true) == null)
    }

    @Test
    fun `bola orchestration fires with two identities and schema`() {
        val same = """{"data":{"user":{"id":"1"}}}"""
        val (ctx, sent) = MockContext.build(
            listOf(rsp(200, same), rsp(200, same)),
            config = CheckConfig(authHeadersA = mapOf("Authorization" to "A"), authHeadersB = mapOf("Authorization" to "B")),
            schema = SchemaFixtures.full(),
        )
        val f = BolaCheck().run(ctx)
        assertEquals(1, f.size)
        assertEquals(2, sent.requests.size) // one per identity
    }

    // ---- BflaCheck (API5) ----
    @Test
    fun `bfla authorized predicate`() {
        assertTrue(BflaCheck.authorized("""{"data":{"adminUsers":{"__typename":"User"}}}""", "adminUsers"))
        assertTrue(!BflaCheck.authorized("""{"data":null,"errors":[{"message":"Forbidden"}]}""", "adminUsers"))
    }

    @Test
    fun `bfla skipped without identity A`() {
        val (ctx, _) = MockContext.build(ok("{}"), schema = SchemaFixtures.full())
        assertTrue(BflaCheck().run(ctx).isEmpty())
    }

    @Test
    fun `bfla fires when low-priv identity reaches privileged query`() {
        val body = """{"data":{"adminUsers":{"__typename":"User"}}}"""
        val (ctx, _) = MockContext.build(
            ok(body),
            config = CheckConfig(authHeadersA = mapOf("Authorization" to "low")),
            schema = SchemaFixtures.full(),
        )
        assertEquals(1, BflaCheck().run(ctx).size)
    }

    // ---- FieldAuthzCheck (API3) ----
    @Test
    fun `field authz exposedFields predicate`() {
        val body = """{"data":{"me":{"password":"h","token":null}}}"""
        assertEquals(listOf("password"), FieldAuthzCheck.exposedFields(body, "me", listOf("password", "token")))
    }

    @Test
    fun `field authz fires when sensitive field returned`() {
        val body = """{"data":{"me":{"password":"h","token":"t"}}}"""
        val (ctx, _) = MockContext.build(ok(body), schema = SchemaFixtures.full())
        val f = FieldAuthzCheck().run(ctx)
        assertEquals(1, f.size)
        assertTrue(f[0].name.contains("password") || f[0].name.contains("token"))
    }

    @Test
    fun `field authz silent when sensitive fields are null`() {
        // me, adminUsers, search all resolve to User with sensitive fields -> probed, all null
        val nulls = listOf(rsp(200, """{"data":{"me":null}}"""),
            rsp(200, """{"data":{"adminUsers":null}}"""),
            rsp(200, """{"data":{"search":null}}"""))
        val (ctx, _) = MockContext.build(nulls, schema = SchemaFixtures.full())
        assertTrue(FieldAuthzCheck().run(ctx).isEmpty())
    }

    // ---- DepthComplexityCheck (API4) ----
    @Test
    fun `depth findCycle locates self-referential field via no-arg root`() {
        val c = DepthComplexityCheck.findCycle(SchemaFixtures.full())!!
        assertEquals("me", c.entryField)
        assertEquals("friends", c.cyclicField)
        assertEquals("User", c.typeName)
    }

    @Test
    fun `depth accepted predicate honors depth-limit errors`() {
        assertTrue(DepthComplexityCheck.accepted("""{"data":{"me":{"friends":{}}}}""", "me"))
        assertTrue(!DepthComplexityCheck.accepted("""{"errors":[{"message":"Query depth limit exceeded"}]}""", "me"))
    }

    @Test
    fun `depth fires when deep query accepted, capped at MAX_DEPTH`() {
        val (ctx, sent) = MockContext.build(
            ok("""{"data":{"me":{"friends":{"__typename":"User"}}}}"""),
            config = CheckConfig(depthProof = 9999),
            schema = SchemaFixtures.full(),
        )
        val f = DepthComplexityCheck().run(ctx)
        assertEquals(1, f.size)
        // Depth is capped: friends nesting count never exceeds MAX_DEPTH.
        val occurrences = Regex("friends").findAll(sent.bodies.first()).count()
        assertTrue(occurrences <= DepthComplexityCheck.MAX_DEPTH)
    }

    // ---- Heuristics ----
    @Test
    fun `heuristics schema analysis`() {
        val s = SchemaFixtures.full()
        assertTrue(Heuristics.sensitiveFields(s).any { it.field == "password" })
        assertEquals(setOf("role", "isAdmin"), Heuristics.massAssignmentSurface(s).map { it.field }.toSet())
        assertTrue(Heuristics.privilegedQueryFields(s).any { it.name == "adminUsers" })
        assertTrue(Heuristics.injectionInsertionPoints(s).size >= 2)
    }
}
