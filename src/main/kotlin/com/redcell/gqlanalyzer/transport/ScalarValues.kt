package com.redcell.gqlanalyzer.transport

/**
 * Sample values for custom GraphQL scalars, used to build minimal operations that pass
 * server-side scalar validation. Everything returns a ready-to-embed GraphQL literal
 * (strings already quoted). Pure and dependency-free.
 */
object ScalarValues {

    private fun norm(s: String) = s.lowercase().replace("_", "").replace("-", "")

    /** Common custom-scalar name → valid literal. Keys are normalized (lowercase, no _/-). */
    private val TABLE: Map<String, String> = mapOf(
        "datetime" to "\"2020-01-01T00:00:00Z\"",
        "datetimeiso" to "\"2020-01-01T00:00:00Z\"",
        "isodatetime" to "\"2020-01-01T00:00:00Z\"",
        "timestamp" to "\"2020-01-01T00:00:00Z\"",
        "date" to "\"2020-01-01\"",
        "time" to "\"00:00:00\"",
        "uuid" to "\"00000000-0000-4000-8000-000000000000\"",
        "guid" to "\"00000000-0000-4000-8000-000000000000\"",
        "email" to "\"test@example.com\"",
        "emailaddress" to "\"test@example.com\"",
        "url" to "\"https://example.com\"",
        "uri" to "\"https://example.com\"",
        "json" to "\"{}\"",
        "jsonobject" to "\"{}\"",
        "bigint" to "1",
        "long" to "1",
        "short" to "1",
        "byte" to "1",
        "decimal" to "1.0",
        "bigdecimal" to "1.0",
        "money" to "1.0",
        "currency" to "\"USD\"",
        "currencycode" to "\"USD\"",
        "countrycode" to "\"US\"",
        "locale" to "\"en-US\"",
        "phone" to "\"+10000000000\"",
        "phonenumber" to "\"+10000000000\"",
        "msisdn" to "\"+10000000000\"",
        "hexcolor" to "\"#000000\"",
        "hexcolorcode" to "\"#000000\"",
        "color" to "\"#000000\"",
        "ip" to "\"127.0.0.1\"",
        "ipaddress" to "\"127.0.0.1\"",
        "ipv4" to "\"127.0.0.1\"",
        "port" to "1",
        "base64" to "\"dGVzdA==\"",
        "latitude" to "0.0",
        "longitude" to "0.0",
        "void" to "null",
    )

    /** A valid literal for a named custom scalar, or null if unknown. */
    fun sampleFor(typeName: String): String? = TABLE[norm(typeName)]

    /**
     * Best-effort value for [typeName] given the server's coercion [errorMessage]:
     * the scalar table first, then constraints mined from the message. Null if nothing fits.
     */
    fun synthesize(typeName: String, errorMessage: String): String? {
        sampleFor(typeName)?.let { return it }
        return mineFromError(errorMessage)
    }

    private val EXACT_LEN = Regex("""exactly (\d+) characters""", RegexOption.IGNORE_CASE)
    private val BEGINS_WITH = Regex("""(?:begins?|starts?) with ["']?([A-Za-z0-9_\-]+)["']?""", RegexOption.IGNORE_CASE)
    private val ONE_OF = Regex("""(?:one of|must be):?\s*\[?\s*["']?([A-Za-z0-9_\-]+)""", RegexOption.IGNORE_CASE)
    private val INTEGERISH = Regex("""(integer|numeric|digit|number)""", RegexOption.IGNORE_CASE)
    private val DATETIMEISH = Regex("""date[\s-]?time""", RegexOption.IGNORE_CASE)
    private val DATEISH = Regex("""\bdate\b""", RegexOption.IGNORE_CASE)

    private fun mineFromError(message: String): String? {
        EXACT_LEN.find(message)?.let { m ->
            val n = m.groupValues[1].toIntOrNull() ?: return@let
            if (n in 1..512) {
                val ch = if (INTEGERISH.containsMatchIn(message)) '0' else 'a'
                return "\"" + ch.toString().repeat(n) + "\""
            }
        }
        BEGINS_WITH.find(message)?.let { m ->
            val prefix = m.groupValues[1]
            val pad = (12 - prefix.length).coerceAtLeast(0)
            return "\"" + prefix + "0".repeat(pad) + "\""
        }
        // Order matters: date-time before plain date.
        if (DATETIMEISH.containsMatchIn(message)) return "\"2020-01-01T00:00:00Z\""
        if (DATEISH.containsMatchIn(message)) return "\"2020-01-01\""
        ONE_OF.find(message)?.let { return "\"" + it.groupValues[1] + "\"" }
        return null
    }
}
