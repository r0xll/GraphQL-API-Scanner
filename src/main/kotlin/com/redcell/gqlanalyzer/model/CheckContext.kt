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
    /** Optional: a known object id that belongs to identity A, for a FIRM BOLA proof. */
    val knownObjectId: String? = null,
    /** Max nesting depth for the single depth-proof query. Never escalated. */
    val depthProof: Int = 10,
    /** A known-valid identifier (username/email) for the user-enumeration probe. */
    val userEnumValid: String? = null,
    /** A known-invalid identifier for the user-enumeration probe. */
    val userEnumInvalid: String? = null,
) {
    val hasTwoIdentities: Boolean get() = authHeadersA.isNotEmpty() && authHeadersB.isNotEmpty()

    val hasUserEnumConfig: Boolean
        get() = !userEnumValid.isNullOrBlank() && !userEnumInvalid.isNullOrBlank()
}

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
