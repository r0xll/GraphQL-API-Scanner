package com.redcell.gqlanalyzer.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SchemaReconstructorTest {

    // Canned graphql-js "Did you mean" fixtures.
    private val single = """Cannot query field "usr" on type "Query". Did you mean "user"?"""
    private val multi =
        """Cannot query field "x" on type "User". Did you mean "email", "name", or "id"?"""
    private val pairForm = """Did you mean "a" or "b"?"""
    private val noSuggestion = """Syntax Error: Expected Name, found "}"."""

    @Test
    fun `parses a single suggestion with its type`() {
        val fs = SchemaReconstructor.parseMessage(single)!!
        assertEquals("Query", fs.onType)
        assertEquals(listOf("user"), fs.suggestions)
    }

    @Test
    fun `parses multiple comma-and-or suggestions`() {
        val fs = SchemaReconstructor.parseMessage(multi)!!
        assertEquals("User", fs.onType)
        assertEquals(listOf("email", "name", "id"), fs.suggestions)
    }

    @Test
    fun `parses the two-option 'or' form without a type`() {
        val fs = SchemaReconstructor.parseMessage(pairForm)!!
        assertNull(fs.onType)
        assertEquals(listOf("a", "b"), fs.suggestions)
    }

    @Test
    fun `returns null when there is no suggestion`() {
        assertNull(SchemaReconstructor.parseMessage(noSuggestion))
    }

    @Test
    fun `harvest flattens and dedupes across messages`() {
        val all = SchemaReconstructor.harvest(listOf(single, multi, pairForm, noSuggestion))
        assertEquals(setOf("user", "email", "name", "id", "a", "b"), all)
    }

    @Test
    fun `reconstruct groups suggestions by type`() {
        val r = SchemaReconstructor.reconstruct(listOf(single, multi, pairForm, noSuggestion))
        assertEquals(setOf("user"), r.suggestionsByType["Query"])
        assertEquals(setOf("email", "name", "id"), r.suggestionsByType["User"])
        assertTrue("Query" in r.suggestionsByType && "User" in r.suggestionsByType)
    }

    @Test
    fun `toSchemaModel builds a partial OBJECT-shell schema flagged reconstructed`() {
        val r = SchemaReconstructor.reconstruct(listOf(single, multi))
        val model = SchemaReconstructor.toSchemaModel(r)!!
        assertTrue(model.reconstructed)
        assertEquals("Query", model.queryTypeName)
        val userFields = model.type("User")!!.fields.map { it.name }.toSet()
        assertEquals(setOf("email", "name", "id"), userFields)
    }

    @Test
    fun `empty input yields null model`() {
        assertNull(SchemaReconstructor.toSchemaModel(SchemaReconstructor.reconstruct(emptyList())))
    }
}
