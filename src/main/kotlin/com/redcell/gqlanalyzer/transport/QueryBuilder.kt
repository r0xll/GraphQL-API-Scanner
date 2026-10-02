package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.SchemaModel

/** Builds concrete GraphQL operation strings from schema fragments. */
object QueryBuilder {

    /** GraphQL literal: bare for ints/bools, quoted+escaped otherwise. */
    fun literal(value: String): String {
        if (value.matches(Regex("""-?\d+"""))) return value
        if (value == "true" || value == "false") return value
        return "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""
    }

    /** Minimal selection set needed for a field's return type (empty for scalar/enum). */
    fun selectionFor(schema: SchemaModel, field: GqlField): String {
        val rt = schema.type(field.typeRef.namedType())
        return when (rt?.kind) {
            "OBJECT", "INTERFACE", "UNION" -> " { __typename }"
            else -> ""
        }
    }

    /** `{ field(arg: <literal>)<selection> }` */
    fun singleArgQuery(schema: SchemaModel, field: GqlField, argName: String, argValue: String): String =
        "{ ${field.name}($argName: ${literal(argValue)})${selectionFor(schema, field)} }"

    /** `{ field<selection> }` with no args. */
    fun bareFieldQuery(schema: SchemaModel, field: GqlField): String =
        "{ ${field.name}${selectionFor(schema, field)} }"

    /** `{ root { leaf1 leaf2 ... } }` */
    fun selectLeaves(root: GqlField, leaves: List<String>): String =
        "{ ${root.name} { ${leaves.joinToString(" ")} } }"

    /** One deeply-nested query over a self-referential field. Depth is capped by caller; no escalation. */
    fun deepQuery(entryField: String, cyclicField: String, depth: Int): String {
        var inner = "__typename"
        repeat(depth) { inner = "$cyclicField { $inner }" }
        return "{ $entryField { $inner } }"
    }
}
