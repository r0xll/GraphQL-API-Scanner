package com.redcell.gqlanalyzer.transport

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject

/** Pure predicates over GraphQL response bodies used by the checks. */
object GraphQLResponses {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private fun dataObject(body: String): JsonObject? {
        val root = runCatching { json.parseToJsonElement(body) }.getOrNull() as? JsonObject ?: return null
        return root["data"] as? JsonObject
    }

    /** The value of data.<field>, or null if absent/JSON-null/unparseable. */
    fun dataField(body: String, field: String): JsonElement? =
        dataObject(body)?.get(field)?.takeIf { it !is JsonNull }

    fun fieldNonNull(body: String, field: String): Boolean = dataField(body, field) != null

    /** Same non-null value returned for the field in both bodies (object leaked across identities). */
    fun fieldEqualNonNull(bodyA: String, bodyB: String, field: String): Boolean {
        val a = dataField(bodyA, field) ?: return false
        val b = dataField(bodyB, field) ?: return false
        return a == b
    }

    /** Every alias key is present and non-null in a single response's `data`. */
    fun aliasesResolved(body: String, aliases: List<String>): Boolean {
        if (aliases.isEmpty()) return false
        val data = dataObject(body) ?: return false
        return aliases.all { it in data.keys && data[it] !is JsonNull }
    }

    /** Top-level JSON array of >= n envelopes, each with non-null `data`. */
    fun arrayBatchResolved(body: String, n: Int): Boolean {
        val root = runCatching { json.parseToJsonElement(body) }.getOrNull() as? JsonArray ?: return false
        if (root.size < n) return false
        return root.all { el ->
            val d = (el as? JsonObject)?.get("data")
            d != null && d !is JsonNull
        }
    }
}

/** Builds alias-batched queries of benign fields. */
object AliasBatch {
    /** `{ a0: __typename a1: __typename ... }` plus the alias names, capped by caller. */
    fun aliasQuery(n: Int, field: String = "__typename"): Pair<String, List<String>> {
        val names = (0 until n).map { "a$it" }
        val body = "{ " + names.joinToString(" ") { "$it: $field" } + " }"
        return body to names
    }
}
