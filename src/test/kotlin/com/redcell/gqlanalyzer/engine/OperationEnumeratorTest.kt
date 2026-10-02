package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.SchemaFixtures
import com.redcell.gqlanalyzer.model.OperationKind
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OperationEnumeratorTest {

    @Test
    fun `enumerates query and mutation root fields as operations`() {
        val ops = OperationEnumerator.enumerate(SchemaFixtures.full())
        val byName = ops.associateBy { it.name }

        // Queries: user, me, adminUsers, search
        assertTrue("QUERY.user" in byName)
        assertTrue("QUERY.me" in byName)
        assertTrue("QUERY.adminUsers" in byName)
        assertTrue("QUERY.search" in byName)
        // Mutation: updateUser
        assertTrue("MUTATION.updateUser" in byName)

        assertEquals(OperationKind.QUERY, byName["QUERY.user"]!!.kind)
        assertEquals(OperationKind.MUTATION, byName["MUTATION.updateUser"]!!.kind)
    }

    @Test
    fun `requiresArgs reflects non-null arguments`() {
        val ops = OperationEnumerator.enumerate(SchemaFixtures.full()).associateBy { it.name }
        assertTrue(ops["QUERY.user"]!!.requiresArgs)   // id: ID!
        assertTrue(!ops["QUERY.me"]!!.requiresArgs)    // no args
        assertTrue(!ops["QUERY.search"]!!.requiresArgs) // term: String (optional)
    }

    @Test
    fun `benign schema yields only its query fields`() {
        val ops = OperationEnumerator.enumerate(SchemaFixtures.benign())
        assertEquals(listOf("QUERY.health"), ops.map { it.name })
    }
}
