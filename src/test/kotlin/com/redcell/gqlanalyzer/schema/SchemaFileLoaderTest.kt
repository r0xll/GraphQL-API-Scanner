package com.redcell.gqlanalyzer.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SchemaFileLoaderTest {

    private val schemaBody =
        """"queryType":{"name":"Query"},"mutationType":null,"subscriptionType":null,""" +
            """"types":[{"kind":"OBJECT","name":"Query","fields":[""" +
            """{"name":"me","args":[],"type":{"kind":"OBJECT","name":"User","ofType":null}}]}]"""

    @Test
    fun `loads full introspection JSON (data wrapper)`() {
        val m = SchemaFileLoader.load("""{"data":{"__schema":{$schemaBody}}}""")!!
        assertEquals("Query", m.queryTypeName)
        assertTrue(m.typesByName.containsKey("Query"))
    }

    @Test
    fun `loads bare __schema JSON`() {
        val m = SchemaFileLoader.load("""{"__schema":{$schemaBody}}""")!!
        assertEquals("Query", m.queryTypeName)
    }

    @Test
    fun `loads a bare schema-object JSON`() {
        val m = SchemaFileLoader.load("{$schemaBody}")!!
        assertEquals("Query", m.queryTypeName)
        assertTrue(m.queries().any { it.name == "me" })
    }

    @Test
    fun `loads SDL`() {
        val sdl = """
            type Query { user(id: ID!): User me: User }
            type User { id: ID! email: String }
        """.trimIndent()
        val m = SchemaFileLoader.load(sdl)!!
        assertEquals("Query", m.queryTypeName)
        assertTrue(m.queries().any { it.name == "user" })
    }

    @Test
    fun `returns null on garbage`() {
        assertNull(SchemaFileLoader.load("this is not a schema"))
        assertNull(SchemaFileLoader.load(""))
        assertNull(SchemaFileLoader.load("{ not valid json"))
    }
}
