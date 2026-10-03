package com.redcell.gqlanalyzer.checks

/**
 * graphw00f-style engine fingerprints: distinctive error/response markers that
 * identify the GraphQL server implementation. Matching is best-effort — the first
 * engine with any marker hit wins (ordered most-specific first).
 */
object EngineFingerprints {

    data class Engine(val name: String, val markers: List<Regex>)

    val ENGINES: List<Engine> = listOf(
        Engine(
            "Apollo Server",
            listOf(
                Regex("""(?i)Cannot query field .* on type"""),
                Regex("""(?i)Did you mean to use an inline fragment"""),
                Regex("""(?i)apollo"""),
                Regex("""(?i)PersistedQueryNotFound"""),
            ),
        ),
        Engine(
            "graphql-js (Express/graphql-http)",
            listOf(
                Regex("""(?i)Syntax Error: Expected Name, found"""),
                Regex("""(?i)Must provide query string"""),
                Regex("""(?i)Cannot query field .* Did you mean"""),
            ),
        ),
        Engine(
            "graphql-java",
            listOf(
                Regex("""(?i)Validation error of type \w+"""),
                Regex("""(?i)Invalid Syntax : offending token"""),
                Regex("""(?i)FieldUndefined"""),
            ),
        ),
        Engine(
            "Graphene (Python)",
            listOf(
                Regex("""(?i)Syntax Error GraphQL \(\d+:\d+\)"""),
                Regex("""(?i)graphene"""),
            ),
        ),
        Engine(
            "Ariadne (Python)",
            listOf(Regex("""(?i)The query must be a string""")),
        ),
        Engine(
            "Hasura",
            listOf(
                Regex("""(?i)x-hasura"""),
                Regex("""(?i)field \\?".*\\?" not found in type"""),
                Regex("""(?i)no such type exists in the schema"""),
            ),
        ),
        Engine(
            "Ruby graphql / graphql-ruby",
            listOf(
                Regex("""(?i)Field '.*' doesn't exist on type"""),
                Regex("""(?i)is not defined on type"""),
            ),
        ),
        Engine(
            "Sangria (Scala)",
            listOf(Regex("""(?i)Query does not pass validation"""), Regex("""(?i)sangria""")),
        ),
        Engine(
            "HyperGraphQL",
            listOf(Regex("""(?i)Validation error.*InvalidSyntax"""), Regex("""(?i)hypergraphql""")),
        ),
        Engine(
            "Lighthouse (PHP/Laravel)",
            listOf(Regex("""(?i)Internal server error"""), Regex("""(?i)lighthouse"""), Regex("""(?i)nuwave""")),
        ),
    )

    /** First engine whose markers appear across the given response bodies, else null. */
    fun identify(bodies: List<String>): String? {
        val haystack = bodies.joinToString("\n")
        return ENGINES.firstOrNull { e -> e.markers.any { it.containsMatchIn(haystack) } }?.name
    }
}
