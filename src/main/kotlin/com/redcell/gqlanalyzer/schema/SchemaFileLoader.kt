package com.redcell.gqlanalyzer.schema

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/**
 * Loads an operator-supplied, out-of-band schema file into a [SchemaModel]. Accepts an
 * introspection JSON dump (in its common shapes) or GraphQL SDL. Pure and defensive:
 * returns null on anything it cannot parse, never throws.
 */
object SchemaFileLoader {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    fun load(text: String): SchemaModel? {
        val t = text.trim()
        if (t.isEmpty()) return null
        return if (t.startsWith("{") || t.startsWith("[")) loadJson(t) else SdlParser.parse(t)
    }

    /** Normalize the common introspection JSON shapes to `{"data":{"__schema":…}}` and parse. */
    private fun loadJson(text: String): SchemaModel? {
        val root = runCatching { json.parseToJsonElement(text) }.getOrNull() as? JsonObject ?: return null
        val normalized = when {
            root.containsKey("data") -> text // already {"data":{"__schema":…}}
            root.containsKey("__schema") -> wrap("data", root) // {"__schema":…}
            root.containsKey("queryType") || root.containsKey("types") ->
                buildJsonObject { put("data", wrapObj("__schema", root)) }.toString() // bare __schema body
            else -> return null
        }
        return IntrospectionParser.parse(normalized)
    }

    private fun wrap(key: String, value: JsonObject): String =
        buildJsonObject { put(key, value) }.toString()

    private fun wrapObj(key: String, value: JsonObject): JsonObject =
        buildJsonObject { put(key, value) }
}
