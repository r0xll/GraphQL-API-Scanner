package com.redcell.gqlanalyzer.transport

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.put

/**
 * Thin helpers for composing and sending GraphQL requests off a base request.
 * Body composition is pure/testable; sending goes through Montoya.
 */
object GraphQLHttp {

    val json = Json { ignoreUnknownKeys = true; isLenient = true }

    /** Single GraphQL envelope: {"query":..., "variables":..., "operationName":...}. */
    fun queryEnvelope(query: String, variables: JsonObject? = null, operationName: String? = null): String =
        buildJsonObject {
            put("query", query)
            if (operationName != null) put("operationName", operationName)
            if (variables != null) put("variables", variables)
        }.toString()

    /** JSON array batch of envelopes (APOLLO-style batching). Caller MUST keep size <= proof cap. */
    fun batchEnvelope(queries: List<String>): String =
        "[" + queries.joinToString(",") { queryEnvelope(it) } + "]"

    /** POST the given JSON body as application/json on the base request's service. */
    fun postJson(
        api: MontoyaApi,
        base: HttpRequest,
        body: String,
        extraHeaders: Map<String, String> = emptyMap(),
    ): HttpRequestResponse {
        var req = base.withMethod("POST")
            .withBody(body)
            .withUpdatedHeader("Content-Type", "application/json")
        for ((k, v) in extraHeaders) req = req.withUpdatedHeader(k, v)
        return api.http().sendRequest(req)
    }

    /** Send an arbitrary already-built request. */
    fun send(api: MontoyaApi, req: HttpRequest): HttpRequestResponse = api.http().sendRequest(req)

    /** Top-level GraphQL error messages from a response body (empty on parse failure). */
    fun errorMessages(responseBody: String): List<String> {
        val root = runCatching { json.parseToJsonElement(responseBody) }.getOrNull() ?: return emptyList()
        return collectErrors(root)
    }

    private fun collectErrors(el: JsonElement): List<String> = buildList {
        when (el) {
            is JsonObject -> el["errors"]?.let { errs ->
                runCatching { errs.jsonArray }.getOrNull()?.forEach { e ->
                    runCatching { e.jsonObject["message"]?.let { m -> add(m.toString().trim('"')) } }
                }
            }
            else -> {}
        }
    }

    /** True if the body is a JSON object carrying a non-null top-level "data". */
    fun hasData(responseBody: String): Boolean {
        val root = runCatching { json.parseToJsonElement(responseBody) }.getOrNull() as? JsonObject ?: return false
        val data = root["data"] ?: return false
        return data !is kotlinx.serialization.json.JsonNull
    }
}
