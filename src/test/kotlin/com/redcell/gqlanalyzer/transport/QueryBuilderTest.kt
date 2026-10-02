package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.checks.SchemaFixtures
import com.redcell.gqlanalyzer.engine.OperationEnumerator
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class QueryBuilderTest {

    private fun scalar(name: String) = GqlTypeRef(kind = "SCALAR", name = name)
    private fun nonNull(ref: GqlTypeRef) = GqlTypeRef(kind = "NON_NULL", ofType = ref)

    @Test
    fun `placeholder maps scalars by name`() {
        val s = SchemaFixtures.full()
        assertEquals("1", QueryBuilder.placeholderFor(s, scalar("Int")))
        assertEquals("1.5", QueryBuilder.placeholderFor(s, scalar("Float")))
        assertEquals("true", QueryBuilder.placeholderFor(s, scalar("Boolean")))
        assertEquals("\"1\"", QueryBuilder.placeholderFor(s, scalar("ID")))
        assertEquals("\"test\"", QueryBuilder.placeholderFor(s, scalar("String")))
        // NON_NULL is unwrapped.
        assertEquals("\"1\"", QueryBuilder.placeholderFor(s, nonNull(scalar("ID"))))
    }

    @Test
    fun `placeholder picks a bare enum value`() {
        val enumType = GqlType("Role", "ENUM", enumValues = listOf("USER", "ADMIN"))
        val schema = SchemaModel("Query", null, null, listOf(enumType))
        assertEquals("USER", QueryBuilder.placeholderFor(schema, GqlTypeRef(kind = "ENUM", name = "Role")))
    }

    @Test
    fun `placeholder builds a minimal input object with required fields only`() {
        val input = GqlType(
            "CreateUserInput", "INPUT_OBJECT",
            inputFields = listOf(
                GqlInputValue("email", nonNull(scalar("String"))), // required
                GqlInputValue("nickname", scalar("String")),       // optional -> omitted
            ),
        )
        val schema = SchemaModel("Query", null, null, listOf(input))
        val lit = QueryBuilder.placeholderFor(schema, GqlTypeRef(kind = "INPUT_OBJECT", name = "CreateUserInput"))
        assertTrue(lit.contains("email: \"test\""))
        assertTrue(!lit.contains("nickname"))
    }

    @Test
    fun `recursive input object is bounded by the depth cap`() {
        // Node { child: Node! } -> must terminate at the cap, not stack-overflow.
        val node = GqlType(
            "Node", "INPUT_OBJECT",
            inputFields = listOf(GqlInputValue("child", nonNull(GqlTypeRef(kind = "INPUT_OBJECT", name = "Node")))),
        )
        val schema = SchemaModel("Query", null, null, listOf(node))
        val lit = QueryBuilder.placeholderFor(schema, GqlTypeRef(kind = "INPUT_OBJECT", name = "Node"))
        assertTrue(lit.startsWith("{"))
        assertTrue(lit.endsWith("}"))
    }

    @Test
    fun `operationDocument fills required args and omits optional ones`() {
        val schema = SchemaFixtures.full()
        val ops = OperationEnumerator.enumerate(schema).associateBy { it.name }

        val userDoc = QueryBuilder.operationDocument(schema, ops["QUERY.user"]!!)
        assertEquals("query { user(id: \"1\") { __typename } }", userDoc)

        val searchDoc = QueryBuilder.operationDocument(schema, ops["QUERY.search"]!!)
        assertTrue(!searchDoc.contains("term:")) // optional arg omitted
        assertTrue(searchDoc.startsWith("query { search"))

        val mutationDoc = QueryBuilder.operationDocument(schema, ops["MUTATION.updateUser"]!!)
        assertTrue(mutationDoc.startsWith("mutation { updateUser"))
    }

    @Test
    fun `operationDocument selects sensitive leaves when provided`() {
        val schema = SchemaFixtures.full()
        val me = OperationEnumerator.enumerate(schema).first { it.name == "QUERY.me" }
        val doc = QueryBuilder.operationDocument(schema, me, listOf("password", "token"))
        assertEquals("query { me { password token } }", doc)
    }
}
