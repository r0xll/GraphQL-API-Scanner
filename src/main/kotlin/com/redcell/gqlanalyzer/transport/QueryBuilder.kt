package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.checks.Heuristics
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

    /**
     * A root query injecting [value] into [argName], filling any other required args
     * with typed placeholders. Used by active OOB checks to place a Collaborator
     * hostname into a specific argument.
     */
    fun injectedQuery(schema: SchemaModel, field: GqlField, argName: String, value: String): String {
        val others = field.args
            .filter { it.typeRef.isNonNull() && it.name != argName }
            .joinToString("") { "${it.name}: ${placeholderFor(schema, it.typeRef)}, " }
        val args = "$others$argName: ${literal(value)}"
        return "query { ${field.name}($args)${selectionFor(schema, field)} }"
    }

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
        "String" -> "\"test\""
        // Custom scalars: use a format-appropriate sample when we recognize the name.
        else -> ScalarValues.sampleFor(name) ?: "\"test\""
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

    /**
     * `(a: v, b: w)` filling required args only; empty string when there are none.
     * [overrides] (arg name → literal) take precedence over generated placeholders —
     * used by the adaptive scanner to feed back values that satisfy scalar validation.
     */
    fun argsFor(schema: SchemaModel, field: GqlField, overrides: Map<String, String> = emptyMap()): String {
        val required = field.args.filter { it.typeRef.isNonNull() }
        if (required.isEmpty()) return ""
        return "(" + required.joinToString(", ") {
            "${it.name}: ${overrides[it.name] ?: placeholderFor(schema, it.typeRef)}"
        } + ")"
    }

    // ---- injection targeting (top-level AND nested input-object leaves) ----

    /**
     * Field-name paths from each of [field]'s arguments down to a string-backed scalar leaf
     * (`Heuristics.isInjectableScalar`), descending through INPUT_OBJECT args/fields
     * (unwrapping NON_NULL/LIST), required fields only — matching the shape the baseline probe
     * builds. A top-level scalar arg yields a one-element path (`["serial"]`); a nested field
     * yields e.g. `["event","profileId"]`. Depth- and count-capped and cycle-guarded by input type.
     */
    fun injectableLeafPaths(schema: SchemaModel, field: GqlField, maxDepth: Int = 4, maxPoints: Int = 20): List<List<String>> {
        val out = mutableListOf<List<String>>()
        for (arg in field.args) {
            collectLeafPaths(schema, arg.typeRef, listOf(arg.name), 0, maxDepth, emptySet(), maxPoints, out)
            if (out.size >= maxPoints) break
        }
        return out.take(maxPoints)
    }

    private fun collectLeafPaths(
        schema: SchemaModel,
        typeRef: GqlTypeRef,
        path: List<String>,
        depth: Int,
        maxDepth: Int,
        seen: Set<String>,
        maxPoints: Int,
        out: MutableList<List<String>>,
    ) {
        if (out.size >= maxPoints) return
        val named = typeRef.namedType() ?: return
        val resolved = schema.type(named)
        if (resolved?.kind == "INPUT_OBJECT") {
            if (depth >= maxDepth || named in seen) return
            for (f in resolved.inputFields.filter { it.typeRef.isNonNull() }) {
                collectLeafPaths(schema, f.typeRef, path + f.name, depth + 1, maxDepth, seen + named, maxPoints, out)
                if (out.size >= maxPoints) return
            }
        } else if (Heuristics.isInjectableScalar(schema, typeRef)) {
            out += path
        }
    }

    /**
     * A complete operation document that places [payloadLiteral] at the single leaf named by
     * [path] (e.g. `["event","profileId"]`) and keeps every other required arg/field valid
     * (typed placeholders; top-level scalar args honour [overrides] from the adaptive probe).
     * Used by the per-operation injection pass so exactly one field carries the payload.
     */
    fun injectedDocumentForPath(
        schema: SchemaModel,
        op: Operation,
        path: List<String>,
        payloadLiteral: String,
        overrides: Map<String, String> = emptyMap(),
    ): String {
        val keyword = when (op.kind) {
            OperationKind.QUERY -> "query"
            OperationKind.MUTATION -> "mutation"
            OperationKind.SUBSCRIPTION -> "subscription"
        }
        val argName = path.first()
        val rest = path.drop(1)
        val injected = op.field.args.firstOrNull { it.name == argName }
        val parts = mutableListOf<String>()
        if (injected != null) parts += "$argName: ${buildInjectedArgValue(schema, injected.typeRef, rest, payloadLiteral)}"
        for (a in op.field.args) {
            if (a.name == argName || !a.typeRef.isNonNull()) continue
            parts += "${a.name}: ${overrides[a.name] ?: placeholderFor(schema, a.typeRef)}"
        }
        val args = if (parts.isEmpty()) "" else "(" + parts.joinToString(", ") + ")"
        return "$keyword { ${op.field.name}$args${selectionFor(schema, op.field)} }"
    }

    /** Build an arg/field value, placing [payloadLiteral] at the end of [remaining] (empty ⇒ here). */
    private fun buildInjectedArgValue(schema: SchemaModel, typeRef: GqlTypeRef, remaining: List<String>, payloadLiteral: String): String {
        when (typeRef.kind) {
            "NON_NULL" -> return buildInjectedArgValue(schema, typeRef.ofType ?: return "null", remaining, payloadLiteral)
            "LIST" -> return "[" + buildInjectedArgValue(schema, typeRef.ofType ?: return "null", remaining, payloadLiteral) + "]"
        }
        if (remaining.isEmpty()) return payloadLiteral // the injected leaf
        val resolved = typeRef.namedType()?.let { schema.type(it) }
        if (resolved?.kind == "INPUT_OBJECT") {
            val target = remaining.first()
            val body = resolved.inputFields.filter { it.typeRef.isNonNull() }.joinToString(", ") { f ->
                val v = if (f.name == target) buildInjectedArgValue(schema, f.typeRef, remaining.drop(1), payloadLiteral)
                else placeholderFor(schema, f.typeRef)
                "${f.name}: $v"
            }
            return "{ $body }"
        }
        return payloadLiteral // defensive: path pointed past a non-object leaf
    }

    /**
     * A complete operation document for one [Operation]. Optional args are omitted;
     * required args get typed placeholders (or [overrides] by arg name). When
     * [selectSensitive] names leaf fields, they are selected instead of `__typename`.
     */
    fun operationDocument(
        schema: SchemaModel,
        op: Operation,
        selectSensitive: List<String> = emptyList(),
        overrides: Map<String, String> = emptyMap(),
    ): String {
        val keyword = when (op.kind) {
            OperationKind.QUERY -> "query"
            OperationKind.MUTATION -> "mutation"
            OperationKind.SUBSCRIPTION -> "subscription"
        }
        val args = argsFor(schema, op.field, overrides)
        val selection = when {
            selectSensitive.isNotEmpty() -> " { ${selectSensitive.joinToString(" ")} }"
            else -> selectionFor(schema, op.field)
        }
        return "$keyword { ${op.field.name}$args$selection }"
    }
}
