package com.redcell.gqlanalyzer.schema

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.transport.GraphQLHttp

/**
 * Fetches and deserializes `__schema`. If introspection is disabled, falls back
 * to [SchemaReconstructor] over any leaked "Did you mean" errors (one probing
 * request only — no brute force here).
 */
class IntrospectionRunner(private val api: MontoyaApi) {

    data class Result(
        /** Full schema when introspection succeeded, partial when reconstructed, null when neither. */
        val schema: SchemaModel?,
        val introspectionEnabled: Boolean,
        val reconstructed: SchemaReconstructor.Reconstructed? = null,
        val evidence: HttpRequestResponse? = null,
    )

    fun run(base: HttpRequest): Result {
        val rr = GraphQLHttp.postJson(api, base, GraphQLHttp.queryEnvelope(Introspection.QUERY))
        val body = rr.response()?.bodyToString().orEmpty()

        val schema = IntrospectionParser.parse(body)
        if (schema != null && schema.types.isNotEmpty()) {
            return Result(schema = schema, introspectionEnabled = true, evidence = rr)
        }

        // Introspection disabled or empty — attempt reconstruction from error text.
        val recon = SchemaReconstructor.reconstruct(GraphQLHttp.errorMessages(body))
        return Result(
            schema = SchemaReconstructor.toSchemaModel(recon),
            introspectionEnabled = false,
            reconstructed = recon,
            evidence = rr,
        )
    }
}
