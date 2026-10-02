package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlInputValue
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel

/** Hand-built SchemaModels for Phase-3 check tests. */
object SchemaFixtures {

    private fun ref(name: String, kind: String = "OBJECT", nonNull: Boolean = false): GqlTypeRef {
        val base = GqlTypeRef(kind = kind, name = name)
        return if (nonNull) GqlTypeRef(kind = "NON_NULL", ofType = base) else base
    }

    private val scalar = GqlTypeRef(kind = "SCALAR", name = "String")

    /**
     * Query { user(id: ID!): User, me: User, adminUsers: [User], node(id: ID!): Node }
     * User { id email password token friends(self): User }
     * Mutation { updateUser(input: UpdateUserInput): User }
     * input UpdateUserInput { email, role, isAdmin }
     */
    fun full(): SchemaModel {
        val user = GqlType(
            name = "User",
            kind = "OBJECT",
            fields = listOf(
                GqlField("id", ref("ID", "SCALAR")),
                GqlField("email", scalar),
                GqlField("password", scalar),
                GqlField("token", scalar),
                GqlField("friends", ref("User")), // self-referential -> depth cycle
            ),
        )
        val query = GqlType(
            name = "Query",
            kind = "OBJECT",
            fields = listOf(
                GqlField("user", ref("User"), args = listOf(GqlInputValue("id", ref("ID", "SCALAR", nonNull = true)))),
                GqlField("me", ref("User")),
                GqlField("adminUsers", ref("User")),
                GqlField(
                    "search",
                    ref("User"),
                    args = listOf(GqlInputValue("term", scalar)),
                ),
            ),
        )
        val input = GqlType(
            name = "UpdateUserInput",
            kind = "INPUT_OBJECT",
            inputFields = listOf(
                GqlInputValue("email", scalar),
                GqlInputValue("role", scalar),
                GqlInputValue("isAdmin", GqlTypeRef(kind = "SCALAR", name = "Boolean")),
            ),
        )
        val mutation = GqlType(
            name = "Mutation",
            kind = "OBJECT",
            fields = listOf(
                GqlField(
                    "updateUser", ref("User"),
                    args = listOf(GqlInputValue("input", ref("UpdateUserInput", "INPUT_OBJECT"))),
                ),
            ),
        )
        return SchemaModel("Query", "Mutation", null, listOf(query, user, input, mutation))
    }

    /** A minimal schema with no sensitive/privileged/injectable surface. */
    fun benign(): SchemaModel {
        val query = GqlType(
            name = "Query",
            kind = "OBJECT",
            fields = listOf(GqlField("health", GqlTypeRef(kind = "SCALAR", name = "Boolean"))),
        )
        return SchemaModel("Query", null, null, listOf(query))
    }
}
