package com.redcell.gqlanalyzer.model

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.schema.SchemaModel

/**
 * Credentials/tuning for checks, supplied by the operator — never hardcoded.
 * Two-auth-context checks (BOLA/BFLA) read [authHeadersA]/[authHeadersB].
 */
data class CheckConfig(
    /** Low-privilege / victim identity headers, e.g. {"Authorization": "Bearer A"}. */
    val authHeadersA: Map<String, String> = emptyMap(),
    /** Second identity (attacker) headers for cross-tenant / privilege checks. */
    val authHeadersB: Map<String, String> = emptyMap(),
    /** Hard proof-level cap on batched/aliased operations. Never exceed. */
    val maxBatch: Int = 10,
)

/**
 * Everything a check needs: the Montoya API handle, the base GraphQL request to
 * mutate/replay, the parsed schema (null when introspection is disabled and
 * reconstruction yielded nothing), and operator config.
 */
data class CheckContext(
    val api: MontoyaApi,
    val request: HttpRequest,
    val schema: SchemaModel?,
    val config: CheckConfig = CheckConfig(),
)
