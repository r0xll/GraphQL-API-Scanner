package com.redcell.gqlanalyzer.schema

/**
 * Clairvoyance-style schema reconstruction: when introspection is disabled,
 * graphql-js (and work-alikes) still leak field/type/argument names through
 * "Did you mean ..." validation errors. This harvests those suggestions from
 * error messages via regex — no requests are sent here; callers feed it the
 * error strings they collected.
 *
 * Example graphql-js messages handled:
 *   Cannot query field "usr" on type "Query". Did you mean "user"?
 *   Cannot query field "x" on type "User". Did you mean "email", "name", or "id"?
 *   Did you mean "a" or "b"?
 */
object SchemaReconstructor {

    private val DID_YOU_MEAN = Regex("""[Dd]id you mean (.+?)\?""")
    private val QUOTED = Regex("\"([^\"]+)\"")
    private val ON_TYPE = Regex("""on type \"([^\"]+)\"""")

    data class FieldSuggestion(
        val onType: String?,
        val suggestions: List<String>,
        val sourceMessage: String,
    )

    data class Reconstructed(
        val raw: List<FieldSuggestion>,
    ) {
        /** All harvested names (fields/types/args), de-duplicated. */
        val allSuggestions: Set<String> = raw.flatMap { it.suggestions }.toSet()

        /** Suggestions grouped by the type they were reported on (when known). */
        val suggestionsByType: Map<String, Set<String>> =
            raw.filter { it.onType != null }
                .groupBy({ it.onType!! }, { it.suggestions })
                .mapValues { (_, v) -> v.flatten().toSet() }

        val isEmpty: Boolean get() = raw.isEmpty()
    }

    /** Parse one error message into a suggestion, or null if it carries none. */
    fun parseMessage(message: String): FieldSuggestion? {
        val dym = DID_YOU_MEAN.find(message) ?: return null
        val suggestions = QUOTED.findAll(dym.groupValues[1]).map { it.groupValues[1] }.toList()
        if (suggestions.isEmpty()) return null
        val onType = ON_TYPE.find(message)?.groupValues?.get(1)
        return FieldSuggestion(onType = onType, suggestions = suggestions, sourceMessage = message)
    }

    fun reconstruct(errorMessages: List<String>): Reconstructed =
        Reconstructed(errorMessages.mapNotNull(::parseMessage))

    /** Convenience: flat set of all names leaked across the given messages. */
    fun harvest(errorMessages: List<String>): Set<String> =
        reconstruct(errorMessages).allSuggestions

    /**
     * Build a best-effort partial [SchemaModel] from harvested suggestions.
     * Only type/field names are known (no arg or return types), so types are
     * OBJECT shells with fields carrying an unknown scalar typeRef.
     */
    fun toSchemaModel(reconstructed: Reconstructed, rootQueryType: String = "Query"): SchemaModel? {
        if (reconstructed.isEmpty) return null
        val unknown = GqlTypeRef(kind = "SCALAR", name = "Unknown")
        val types = reconstructed.suggestionsByType.map { (typeName, fields) ->
            GqlType(
                name = typeName,
                kind = "OBJECT",
                fields = fields.map { GqlField(name = it, typeRef = unknown) },
            )
        }
        val hasRoot = types.any { it.name == rootQueryType }
        return SchemaModel(
            queryTypeName = if (hasRoot) rootQueryType else types.firstOrNull()?.name,
            mutationTypeName = null,
            subscriptionTypeName = null,
            types = types,
            reconstructed = true,
        )
    }
}
