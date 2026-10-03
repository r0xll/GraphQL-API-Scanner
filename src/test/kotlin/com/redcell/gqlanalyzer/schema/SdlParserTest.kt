package com.redcell.gqlanalyzer.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SdlParserTest {

    private val sdl = """
        # a comment
        ""${'"'} The root query ""${'"'}
        schema { query: Query mutation: Mutation }

        type Query {
          user(id: ID!): User
          search(term: String, first: Int = 10): [User!]
          legacy: String @deprecated(reason: "use user")
        }

        type Mutation {
          updateUser(input: UpdateUserInput!): User
        }

        type User implements Node {
          id: ID!
          email: String
          roles: [Role!]!
        }

        input UpdateUserInput { email: String, role: Role }
        enum Role { USER ADMIN }
        scalar DateTime
    """.trimIndent()

    @Test
    fun `parses roots from schema block`() {
        val m = SdlParser.parse(sdl)!!
        assertEquals("Query", m.queryTypeName)
        assertEquals("Mutation", m.mutationTypeName)
        assertNull(m.subscriptionTypeName)
    }

    @Test
    fun `parses fields, args and required-ness`() {
        val m = SdlParser.parse(sdl)!!
        val user = m.queries().single { it.name == "user" }
        val idArg = user.args.single { it.name == "id" }
        assertTrue(idArg.typeRef.isNonNull())
        assertEquals("ID", idArg.typeRef.namedType())
        assertEquals("User", user.typeRef.namedType())

        val search = m.queries().single { it.name == "search" }
        assertTrue(search.args.none { it.typeRef.isNonNull() }) // term + first both optional
        assertEquals("User", search.typeRef.namedType()) // [User!] -> User
    }

    @Test
    fun `captures deprecation`() {
        val m = SdlParser.parse(sdl)!!
        val legacy = m.queries().single { it.name == "legacy" }
        assertTrue(legacy.isDeprecated)
        assertEquals("use user", legacy.deprecationReason)
    }

    @Test
    fun `parses input objects and enums`() {
        val m = SdlParser.parse(sdl)!!
        val input = m.type("UpdateUserInput")!!
        assertEquals("INPUT_OBJECT", input.kind)
        assertTrue(input.inputFields.any { it.name == "role" })
        val role = m.type("Role")!!
        assertEquals("ENUM", role.kind)
        assertEquals(listOf("USER", "ADMIN"), role.enumValues)
    }

    @Test
    fun `defaults roots when no schema block`() {
        val m = SdlParser.parse("type Query { ping: String }")!!
        assertEquals("Query", m.queryTypeName)
    }

    @Test
    fun `type ref parsing handles wrappers`() {
        assertEquals("User", SdlParser.parseTypeRef("[User!]!").namedType())
        assertTrue(SdlParser.parseTypeRef("[User!]!").isNonNull())
        assertTrue(!SdlParser.parseTypeRef("User").isNonNull())
    }
}
