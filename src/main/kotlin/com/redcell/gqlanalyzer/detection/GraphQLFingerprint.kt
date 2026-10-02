package com.redcell.gqlanalyzer.detection

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/**
 * Pure, passive GraphQL fingerprinting. No Montoya types so it is unit-testable
 * with plain strings. [EndpointTagger] adapts live traffic onto these.
 */
object GraphQLFingerprint {

    private val json = Json { ignoreUnknownKeys = true; isLenient = true }

    private val PATH = Regex("""/(graphql|graphiql|playground|altair)\b""", RegexOption.IGNORE_CASE)

    private val TOP_LEVEL_OP_KEYS = setOf("query", "mutation", "operationName")

    fun pathLooksLikeGraphQL(path: String): Boolean = PATH.containsMatchIn(path)

    /** Request body has a top-level query/mutation/operationName (single or batched). */
    fun bodyLooksLikeGraphQL(body: String): Boolean {
        if (body.isBlank()) return false
        val root = runCatching { json.parseToJsonElement(body) }.getOrNull() ?: return false
        return when (root) {
            is JsonObject -> root.keys.any { it in TOP_LEVEL_OP_KEYS }
            is JsonArray -> root.any { el ->
                runCatching { el.jsonObject.keys.any { it in TOP_LEVEL_OP_KEYS } }.getOrDefault(false)
            }
            else -> false
        }
    }

    /** Response carries both top-level "data" and "errors" (the canonical GraphQL error shape). */
    fun responseHasDataAndErrors(body: String): Boolean {
        val root = runCatching { json.parseToJsonElement(body) }.getOrNull() as? JsonObject ?: return false
        return "data" in root.keys && "errors" in root.keys
    }

    data class Detection(val isGraphQL: Boolean, val reasons: List<String>)

    fun classify(path: String, requestBody: String, responseBody: String): Detection {
        val reasons = buildList {
            if (pathLooksLikeGraphQL(path)) add("path matches /(graphql|graphiql|playground|altair)")
            if (bodyLooksLikeGraphQL(requestBody)) add("request body has top-level query/mutation/operationName")
            if (responseHasDataAndErrors(responseBody)) add("response has top-level data+errors")
        }
        return Detection(reasons.isNotEmpty(), reasons)
    }
}
