package com.redcell.gqlanalyzer.schema

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IntrospectionParserTest {

    private val fixture = """
    {
      "data": {
        "__schema": {
          "queryType": { "name": "Query" },
          "mutationType": { "name": "Mutation" },
          "subscriptionType": null,
          "types": [
            {
              "kind": "OBJECT", "name": "Query", "description": "root",
              "fields": [
                { "name": "user", "description": null,
                  "args": [ { "name": "id", "description": null, "defaultValue": null,
                              "type": { "kind": "NON_NULL", "name": null,
                                        "ofType": { "kind": "SCALAR", "name": "ID", "ofType": null } } } ],
                  "type": { "kind": "OBJECT", "name": "User", "ofType": null } }
              ],
              "inputFields": null, "enumValues": null
            },
            {
              "kind": "OBJECT", "name": "Mutation",
              "fields": [
                { "name": "updateUser", "args": [], "type": { "kind": "OBJECT", "name": "User", "ofType": null } }
              ]
            },
            {
              "kind": "OBJECT", "name": "User",
              "fields": [
                { "name": "id", "args": [], "type": { "kind": "SCALAR", "name": "ID", "ofType": null } },
                { "name": "email", "args": [], "type": { "kind": "SCALAR", "name": "String", "ofType": null } }
              ]
            }
          ]
        }
      }
    }
    """.trimIndent()

    @Test
    fun `parses roots and types`() {
        val m = IntrospectionParser.parse(fixture)!!
        assertEquals("Query", m.queryTypeName)
        assertEquals("Mutation", m.mutationTypeName)
        assertNull(m.subscriptionTypeName)
        assertEquals(setOf("Query", "Mutation", "User"), m.typesByName.keys)
    }

    @Test
    fun `resolves wrapped arg type through NON_NULL`() {
        val m = IntrospectionParser.parse(fixture)!!
        val userField = m.queries().single { it.name == "user" }
        val idArg = userField.args.single { it.name == "id" }
        assertTrue(idArg.typeRef.isNonNull())
        assertEquals("ID", idArg.typeRef.namedType())
    }

    @Test
    fun `idBearingFields finds the id-argumented query field`() {
        val m = IntrospectionParser.parse(fixture)!!
        val hits = m.idBearingFields().map { it.second.name }
        assertTrue("user" in hits)
    }

    @Test
    fun `returns null when introspection is disabled`() {
        val disabled = """{"data":null,"errors":[{"message":"GraphQL introspection is not allowed"}]}"""
        assertNull(IntrospectionParser.parse(disabled))
    }
}
