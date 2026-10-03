package com.redcell.gqlanalyzer.schema

/**
 * Pragmatic GraphQL SDL → [SchemaModel] parser for operator-supplied schema files.
 * Covers the common subset: `type`/`interface` (with `implements`), `input`, `enum`,
 * `scalar`, `union`, and a `schema { query/mutation/subscription }` block; field args
 * with defaults; type-ref wrappers (`T`, `T!`, `[T]`, `[T!]!`); and `@deprecated`.
 * Comments (`#`) and descriptions (`"""…"""` / `"…"`) are stripped. Unknown constructs
 * (custom directive definitions, `extend`, unrecognized directives) are tolerated.
 *
 * It is not a spec-complete parser — it recovers the type system needed to enumerate
 * and build operations, nothing more.
 */
object SdlParser {

    fun parse(sdl: String): SchemaModel? {
        val cleaned = stripComments(stripDescriptions(sdl))
        val blocks = topLevelBlocks(cleaned)
        if (blocks.isEmpty()) return null

        val types = mutableListOf<GqlType>()
        var queryName: String? = null
        var mutationName: String? = null
        var subscriptionName: String? = null

        for (b in blocks) {
            when (b.keyword) {
                "type", "interface" -> types += parseObjectLike(b, if (b.keyword == "interface") "INTERFACE" else "OBJECT")
                "input" -> types += parseInput(b)
                "enum" -> types += parseEnum(b)
                "scalar" -> types += GqlType(name = b.name, kind = "SCALAR")
                "union" -> types += GqlType(name = b.name, kind = "UNION")
                "schema" -> {
                    rootBinding(b.body, "query")?.let { queryName = it }
                    rootBinding(b.body, "mutation")?.let { mutationName = it }
                    rootBinding(b.body, "subscription")?.let { subscriptionName = it }
                }
            }
        }
        if (types.isEmpty()) return null

        val names = types.map { it.name }.toSet()
        if (queryName == null && "Query" in names) queryName = "Query"
        if (mutationName == null && "Mutation" in names) mutationName = "Mutation"
        if (subscriptionName == null && "Subscription" in names) subscriptionName = "Subscription"

        return SchemaModel(queryName, mutationName, subscriptionName, types)
    }

    // ---- block splitting ----

    private data class Block(val keyword: String, val name: String, val body: String)

    private val DEF = Regex(
        """\b(type|interface|input|enum|scalar|union|schema)\b\s+([A-Za-z_][A-Za-z0-9_]*)?""",
    )

    /** Split the document into top-level definitions by scanning keyword + brace body. */
    private fun topLevelBlocks(src: String): List<Block> {
        val out = mutableListOf<Block>()
        var i = 0
        while (i < src.length) {
            val m = DEF.find(src, i) ?: break
            val keyword = m.groupValues[1]
            val name = m.groupValues[2]
            var j = m.range.last + 1
            if (keyword == "scalar") { // no body
                out += Block(keyword, name, "")
                i = j
                continue
            }
            if (keyword == "union") {
                val end = src.indexOf('\n', j).let { if (it == -1) src.length else it }
                out += Block(keyword, name, src.substring(j, end))
                i = end
                continue
            }
            // find the matching brace body
            val open = src.indexOf('{', j)
            if (open == -1) { i = j; continue }
            var depth = 0
            var k = open
            while (k < src.length) {
                if (src[k] == '{') depth++
                if (src[k] == '}') { depth--; if (depth == 0) break }
                k++
            }
            val body = if (k < src.length) src.substring(open + 1, k) else src.substring(open + 1)
            out += Block(keyword, name, body)
            i = k + 1
        }
        return out
    }

    // ---- object/interface ----

    private fun parseObjectLike(b: Block, kind: String): GqlType =
        GqlType(name = b.name, kind = kind, fields = parseFields(b.body))

    /** Parse `name(args): Type @dir` field lines from an object body. */
    private fun parseFields(body: String): List<GqlField> {
        val fields = mutableListOf<GqlField>()
        val tokens = splitFields(body)
        for (t in tokens) {
            val fieldRe = Regex("""^([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(([\s\S]*?)\))?\s*:\s*([^@]+?)\s*(@.*)?$""")
            val m = fieldRe.find(t.trim()) ?: continue
            val name = m.groupValues[1]
            val argsRaw = m.groupValues[2]
            val typeRaw = m.groupValues[3].trim()
            val directives = m.groupValues[4]
            fields += GqlField(
                name = name,
                typeRef = parseTypeRef(typeRaw),
                args = if (argsRaw.isBlank()) emptyList() else parseArgs(argsRaw),
                isDeprecated = directives.contains("@deprecated"),
                deprecationReason = deprecationReason(directives),
            )
        }
        return fields
    }

    /** Split a body into field/arg entries at top level (commas, newlines; not inside parens). */
    private fun splitFields(body: String): List<String> {
        val out = mutableListOf<String>()
        val sb = StringBuilder()
        var depth = 0
        for (c in body) {
            when (c) {
                '(', '[', '{' -> { depth++; sb.append(c) }
                ')', ']', '}' -> { depth--; sb.append(c) }
                ',', '\n' -> if (depth == 0) { if (sb.isNotBlank()) out += sb.toString(); sb.clear() } else sb.append(c)
                else -> sb.append(c)
            }
        }
        if (sb.isNotBlank()) out += sb.toString()
        return out
    }

    private fun parseArgs(argsRaw: String): List<GqlInputValue> =
        splitFields(argsRaw).mapNotNull { a ->
            // name: Type [= default]
            val m = Regex("""^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^=@]+?)\s*(?:=\s*([^@]+?))?\s*(@.*)?$""").find(a.trim())
                ?: return@mapNotNull null
            GqlInputValue(
                name = m.groupValues[1],
                typeRef = parseTypeRef(m.groupValues[2].trim()),
                defaultValue = m.groupValues[3].ifBlank { null },
            )
        }

    private fun parseInput(b: Block): GqlType =
        GqlType(name = b.name, kind = "INPUT_OBJECT", inputFields = parseArgs(b.body))

    private fun parseEnum(b: Block): GqlType {
        // Enum values may be space-, comma-, or newline-separated; drop directives/descriptions.
        val values = b.body.split(Regex("[\\s,]+"))
            .map { it.trim() }
            .filter { it.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) }
        return GqlType(name = b.name, kind = "ENUM", enumValues = values)
    }

    // ---- type references ----

    /** Parse `[User!]!` etc. into nested GqlTypeRef; leaf kind "NAMED". */
    fun parseTypeRef(raw: String): GqlTypeRef {
        val s = raw.trim()
        if (s.endsWith("!")) return GqlTypeRef(kind = "NON_NULL", ofType = parseTypeRef(s.dropLast(1)))
        if (s.startsWith("[") && s.endsWith("]")) return GqlTypeRef(kind = "LIST", ofType = parseTypeRef(s.substring(1, s.length - 1)))
        return GqlTypeRef(kind = "NAMED", name = s.takeWhile { it.isLetterOrDigit() || it == '_' })
    }

    // ---- misc ----

    private fun rootBinding(schemaBody: String, op: String): String? =
        Regex("""\b$op\s*:\s*([A-Za-z_][A-Za-z0-9_]*)""").find(schemaBody)?.groupValues?.get(1)

    private fun deprecationReason(directives: String): String? =
        Regex("""@deprecated\s*\(\s*reason\s*:\s*"([^"]*)"""").find(directives)?.groupValues?.get(1)

    private fun stripDescriptions(src: String): String =
        src.replace(Regex("\"\"\"[\\s\\S]*?\"\"\""), "").replace(Regex("(?m)^\\s*\"[^\"\\n]*\"\\s*$"), "")

    private fun stripComments(src: String): String =
        src.lines().joinToString("\n") { line ->
            val q = line.indexOf('#')
            if (q >= 0) line.substring(0, q) else line
        }
}
