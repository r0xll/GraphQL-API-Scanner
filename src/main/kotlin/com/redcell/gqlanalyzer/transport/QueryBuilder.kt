package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.model.OperationKind
import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlTypeRef
import com.redcell.gqlanalyzer.schema.SchemaModel

/** Builds concrete GraphQL operation strings from schema fragments. */
object QueryBuilder {

    private const val INPUT_DEPTH_CAP = 4

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

    // ---- minimal-operation synthesis (for the per-operation crawl/scan) ----

    /**
     * A GraphQL value literal that satisfies the given type for a required argument.
     * Unwraps NON_NULL, fills LIST with a single element, maps scalars by name, picks
     * the first enum value, and builds a minimal object for INPUT_OBJECT (required
     * input fields only). Recursion is bounded and cycle-guarded.
     */
    fun placeholderFor(schema: SchemaModel, type: GqlTypeRef, depth: Int = 0, seen: Set<String> = emptySet()): String {
        when (type.kind) {
            "NON_NULL" -> return placeholderFor(schema, type.ofType ?: return "null", depth, seen)
            "LIST" -> {
                val inner = type.ofType ?: return "[]"
                return "[" + placeholderFor(schema, inner, depth, seen) + "]"
            }
        }
        val named = type.namedType() ?: return "\"test\""
        val resolved = schema.type(named)
        return when (resolved?.kind) {
            "ENUM" -> resolved.enumValues.firstOrNull() ?: "null" // enum literals are bare, unquoted
            "INPUT_OBJECT" -> inputObjectLiteral(schema, resolved.name, depth, seen)
            else -> scalarLiteral(named)
        }
    }

    private fun scalarLiteral(name: String): String = when (name) {
        "Int" -> "1"
        "Float" -> "1.5"
        "Boolean" -> "true"
        "ID" -> "\"1\""
        else -> "\"test\"" // String and custom scalars
    }

    private fun inputObjectLiteral(schema: SchemaModel, typeName: String, depth: Int, seen: Set<String>): String {
        if (depth >= INPUT_DEPTH_CAP || typeName in seen) return "{}"
        val type = schema.type(typeName) ?: return "{}"
        val required = type.inputFields.filter { it.typeRef.isNonNull() }
        val body = required.joinToString(", ") { f ->
            "${f.name}: ${placeholderFor(schema, f.typeRef, depth + 1, seen + typeName)}"
        }
        return "{ $body }"
    }

    /** `(a: v, b: w)` filling required args only; empty string when there are none. */
    fun argsFor(schema: SchemaModel, field: GqlField): String {
        val required = field.args.filter { it.typeRef.isNonNull() }
        if (required.isEmpty()) return ""
        return "(" + required.joinToString(", ") { "${it.name}: ${placeholderFor(schema, it.typeRef)}" } + ")"
    }

    /**
     * A complete operation document for one [Operation]. Optional args are omitted;
     * required args get typed placeholders. When [selectSensitive] names leaf fields,
     * they are selected instead of the default `__typename`, so one probe can surface
     * sensitive-field exposure.
     */
    fun operationDocument(schema: SchemaModel, op: Operation, selectSensitive: List<String> = emptyList()): String {
        val keyword = when (op.kind) {
            OperationKind.QUERY -> "query"
            OperationKind.MUTATION -> "mutation"
            OperationKind.SUBSCRIPTION -> "subscription"
        }
        val args = argsFor(schema, op.field)
        val selection = when {
            selectSensitive.isNotEmpty() -> " { ${selectSensitive.joinToString(" ")} }"
            else -> selectionFor(schema, op.field)
        }
        return "$keyword { ${op.field.name}$args$selection }"
    }
}
