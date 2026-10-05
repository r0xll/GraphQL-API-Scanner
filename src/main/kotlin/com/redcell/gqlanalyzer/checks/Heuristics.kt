package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.GqlType
import com.redcell.gqlanalyzer.schema.SchemaModel

/**
 * Pure name heuristics and schema/response analysis shared by Phase-3 checks.
 * Everything here is deterministic and unit-testable without Montoya.
 */
object Heuristics {

    /** Field names that commonly hold data subject to property-level authz (API3). */
    val SENSITIVE_FIELD = setOf(
        "password", "passwordhash", "passwd", "pwd", "hash", "salt",
        "token", "accesstoken", "refreshtoken", "apikey", "api_key", "secret",
        "ssn", "socialsecurity", "creditcard", "card", "cvv", "pan",
        "privatekey", "sessiontoken", "otp", "mfasecret", "totpsecret",
        "dateofbirth", "dob",
    )

    /** Root field / function names that usually require elevated privilege (API5 BFLA). */
    val PRIVILEGED_FIELD = setOf(
        "admin", "admins", "adminusers", "allusers", "users", "allsecrets",
        "secrets", "auditlog", "auditlogs", "systemconfig", "config",
        "impersonate", "internal", "debug", "metrics",
    )

    /** Input-field names that should never be client-settable (API3 mass assignment). */
    val PRIVILEGED_INPUT = setOf(
        "role", "roles", "isadmin", "admin", "isstaff", "isactive", "active",
        "verified", "isverified", "emailverified", "permissions", "scopes",
        "balance", "credit", "credits", "approved", "status", "accountstatus",
        "tenantid", "ownerid", "userid",
    )

    private fun norm(s: String) = s.lowercase().replace("_", "")

    fun isSensitiveField(name: String) = norm(name) in SENSITIVE_FIELD
    fun isPrivilegedField(name: String) = norm(name) in PRIVILEGED_FIELD
    fun isPrivilegedInput(name: String) = norm(name) in PRIVILEGED_INPUT

    // ---- response-text classification ----

    private val AUTHZ = Regex(
        """(?i)\b(unauthorized|unauthenticated|not\s+authori[sz]ed|forbidden|permission denied|access denied|must be (logged in|authenticated)|requires authentication)\b""",
    )

    private val DEPTH_LIMIT = Regex(
        """(?i)(query depth|maximum depth|depth limit|too deep|exceeds maximum|query complexity|cost limit|too complex)""",
    )

    /** Stack-trace / internal-detail markers that indicate verbose error leakage (API8). */
    private val VERBOSE = listOf(
        Regex("""(?i)exception"""),
        Regex("""\bat [a-zA-Z0-9_.$]+\([A-Za-z0-9_]+\.(java|kt|rb|py|go|cs):\d+\)"""),
        Regex("""(?i)stacktrace"""),
        Regex("""(?i)\b(sqlstate|syntax error at or near|ORA-\d{5}|SQLException|pg_query|mysqli?)\b"""),
        Regex("""(?i)(org\.(hibernate|springframework)|com\.sun|java\.lang\.[A-Za-z]+Exception)"""),
        Regex("""(?i)(/usr/|/var/www/|/home/|[a-zA-Z]:\\\\)"""),
        Regex(""""extensions"\s*:\s*\{[^}]*"(exception|stacktrace|debug)""""),
    )

    fun containsAuthzError(body: String) = AUTHZ.containsMatchIn(body)
    fun containsDepthLimitError(body: String) = DEPTH_LIMIT.containsMatchIn(body)

    fun verboseIndicators(body: String): List<String> =
        VERBOSE.mapNotNull { it.find(body)?.value?.take(80) }

    // ---- schema analysis ----

    data class SensitiveExposure(val onType: String, val field: String)

    fun sensitiveFields(schema: SchemaModel): List<SensitiveExposure> =
        schema.types.filter { it.kind == "OBJECT" || it.kind == "INTERFACE" }
            .flatMap { t -> t.fields.filter { isSensitiveField(it.name) }.map { SensitiveExposure(t.name, it.name) } }

    data class MassAssignRisk(val inputType: String, val field: String)

    fun massAssignmentSurface(schema: SchemaModel): List<MassAssignRisk> =
        schema.types.filter { it.kind == "INPUT_OBJECT" }
            .flatMap { t -> t.inputFields.filter { isPrivilegedInput(it.name) }.map { MassAssignRisk(t.name, it.name) } }

    /** Root query fields that require no mandatory args (safe to probe). */
    fun noArgQueryFields(schema: SchemaModel): List<GqlField> =
        schema.queries().filter { f -> f.args.none { it.typeRef.isNonNull() } }

    fun privilegedQueryFields(schema: SchemaModel): List<GqlField> =
        schema.queries().filter { isPrivilegedField(it.name) }

    /** Leaf (scalar/enum) fields on a type — for building a concrete selection set. */
    fun scalarLeafFields(schema: SchemaModel, type: GqlType): List<GqlField> =
        type.fields.filter { f ->
            val named = f.typeRef.namedType()
            val rt = schema.type(named)
            f.args.none { it.typeRef.isNonNull() } && (rt == null || rt.kind == "SCALAR" || rt.kind == "ENUM")
        }

    /** String/ID argument insertion points across the whole schema, for injection tooling. */
    data class InsertionPoint(val parentType: String, val field: String, val arg: String, val argType: String)

    fun injectionInsertionPoints(schema: SchemaModel): List<InsertionPoint> =
        schema.types.filter { it.kind == "OBJECT" }
            .flatMap { t ->
                t.fields.flatMap { f ->
                    f.args.filter { isInjectableScalar(schema, it.typeRef) }
                        .map { InsertionPoint(t.name, f.name, it.name, it.typeRef.namedType() ?: "?") }
                }
            }

    private val STRINGY = setOf("String", "ID")

    /** Built-in scalars whose values are numeric/boolean — not string-backed injection carriers. */
    private val NON_STRING_BUILTIN_SCALARS = setOf("Int", "Float", "Boolean")

    /**
     * True when [typeRef]'s leaf type is a string-backed scalar an injection payload can ride:
     * the built-in `String`/`ID`, or any **custom scalar** (e.g. `DateTime`, `ProductSerialNumber`,
     * `UUID`), which are serialized as strings and reach the same resolver sinks. Excludes the
     * numeric/boolean built-ins and non-scalar types (enums, input objects, objects).
     *
     * A custom scalar is one the schema declares with kind `SCALAR`; when the schema does not
     * carry the type (reconstructed/partial), fall back to the built-in string names so detection
     * still works without full introspection.
     */
    fun isInjectableScalar(schema: SchemaModel, typeRef: com.redcell.gqlanalyzer.schema.GqlTypeRef): Boolean {
        val named = typeRef.namedType() ?: return false
        if (named in NON_STRING_BUILTIN_SCALARS) return false
        val resolved = schema.type(named)
        return when (resolved?.kind) {
            "SCALAR" -> true           // String, ID, and every custom scalar
            // Type absent from the model (partial/SDL schema): treat an unknown leaf as a
            // custom scalar — it's a string-backed carrier far more often than an undeclared enum.
            null -> true
            else -> false              // ENUM / INPUT_OBJECT / OBJECT / INTERFACE / UNION
        }
    }

    // ---- SSRF insertion points (API7) ----

    /** Argument names that commonly carry a URL/host the server will fetch. */
    val SSRF_ARG = setOf(
        "url", "uri", "href", "link", "webhook", "webhookurl", "callback", "callbackurl",
        "src", "source", "image", "imageurl", "avatar", "avatarurl", "endpoint",
        "redirect", "redirecturl", "dest", "destination", "fetch", "fetchurl", "proxy",
        "target", "targeturl", "next", "nexturl", "returnurl", "origin", "host", "server",
    )

    fun isSsrfArg(name: String) = norm(name) in SSRF_ARG

    /** String/ID args whose name suggests the server will dereference a URL. */
    fun ssrfInsertionPoints(schema: SchemaModel): List<InsertionPoint> =
        schema.types.filter { it.kind == "OBJECT" }
            .flatMap { t ->
                t.fields.flatMap { f ->
                    f.args.filter { it.typeRef.namedType() in STRINGY && isSsrfArg(it.name) }
                        .map { InsertionPoint(t.name, f.name, it.name, it.typeRef.namedType() ?: "?") }
                }
            }

    // ---- in-browser IDE exposure (API8/API9) ----

    private val IDE_MARKERS = listOf(
        Regex("""(?i)<title>\s*graphiql"""),
        Regex("""(?i)graphiql"""),
        Regex("""(?i)graphql\s*playground"""),
        Regex("""(?i)GraphQLPlayground"""),
        Regex("""(?i)\baltair[-_ ]?graphql\b"""),
        Regex("""(?i)altair.*?graphql"""),
        Regex("""(?i)graphql-playground-react"""),
    )

    /** Heuristic: does this HTML body look like a served GraphQL IDE (GraphiQL/Playground/Altair)? */
    fun isGraphqlIdeHtml(body: String): Boolean {
        if (!body.contains("<", ignoreCase = false)) return false // not HTML
        return IDE_MARKERS.any { it.containsMatchIn(body) }
    }

    // ---- DoS: pagination (API4) ----

    /** Argument names that cap list size; a missing server-side limit is a DoS lever. */
    val PAGINATION_ARG = setOf("first", "last", "limit", "count", "pagesize", "perpage", "take", "size", "max")

    fun isPaginationArg(name: String) = norm(name) in PAGINATION_ARG

    private val LIMIT_ERROR = Regex(
        """(?i)(too (many|large)|exceeds?( the)? maximum|must be (less|at most)|limit of \d+|maximum (of |value )?\d+|page size|exceeds limit)""",
    )

    /** Server rejected an oversized request with a limit/cap error. */
    fun containsLimitError(body: String) = LIMIT_ERROR.containsMatchIn(body)

    /** Validation error indicating fragment-cycle detection (the server is protected). */
    private val FRAGMENT_CYCLE = Regex(
        """(?i)(cannot spread fragment|fragment .* cycle|fragment cycle|spread itself|circular (fragment|reference))""",
    )

    fun containsFragmentCycleError(body: String) = FRAGMENT_CYCLE.containsMatchIn(body)

    // ---- authentication (API2) ----

    /** Field names that perform authentication-sensitive operations (rate-limit targets). */
    val AUTH_FIELD = setOf(
        "login", "signin", "authenticate", "auth", "token", "accesstoken", "refreshtoken",
        "signup", "register", "verifyotp", "verify", "verifyemail", "resetpassword",
        "forgotpassword", "changepassword", "updatepassword", "mfa", "totp", "otp", "verifymfa",
    )

    fun isAuthField(name: String) = norm(name) in AUTH_FIELD

    /** Arg names that carry a user identifier (for user-enumeration probing). */
    val IDENTIFIER_ARG = setOf("username", "email", "user", "login", "identifier", "account", "emailaddress", "handle")

    fun isIdentifierArg(name: String) = norm(name) in IDENTIFIER_ARG

    // ---- business-critical flows (API6) ----

    /** Mutation names that drive sensitive business flows warranting manual review. */
    val SENSITIVE_FLOW = setOf(
        "purchase", "buy", "checkout", "order", "placeorder", "pay", "payment", "transfer",
        "withdraw", "deposit", "refund", "payout", "charge", "wire", "redeem", "invite",
        "grant", "promote", "approve", "subscribe", "unsubscribe", "cancel", "delete",
        "remove", "sendmoney", "sendinvite", "addfunds", "changerole", "setrole", "impersonate",
    )

    // Prefix match so compound names (refundOrder, deleteUser, transferFunds) are caught.
    fun isSensitiveFlow(name: String): Boolean {
        val n = norm(name)
        return SENSITIVE_FLOW.any { n == it || n.startsWith(it) }
    }

    // ---- CORS misconfiguration (API8) ----

    /**
     * True when the server reflects an arbitrary [testOrigin] (or `*`) in
     * Access-Control-Allow-Origin together with credentials:true — a credentialed
     * cross-origin read primitive.
     */
    fun corsMisconfig(acao: String?, acac: String?, testOrigin: String): Boolean {
        if (acao == null) return false
        val reflects = acao.trim() == testOrigin || acao.trim() == "*"
        val creds = acac?.trim().equals("true", ignoreCase = true)
        return reflects && creds
    }

    // ---- input/scalar coercion errors (adaptive probing) ----

    private val COERCION = Regex(
        """(?i)(expected (value of )?type|cannot represent|got invalid value|is not a valid|expected type .* found)""",
    )
    private val COERCION_TYPE = Regex("""[Ee]xpected (?:value of )?type\s+["']?([A-Za-z_][A-Za-z0-9_]*)""")

    /** True when a response error is an argument/scalar coercion (validation) error, not authz/exec. */
    fun isInputCoercionError(body: String): Boolean = COERCION.containsMatchIn(body)

    /** The scalar/type name a single coercion error names (`Expected value of type "DateTime!"` → `DateTime`), else null. */
    fun coercionTypeName(message: String): String? = COERCION_TYPE.find(message)?.groupValues?.get(1)

    // ---- active in-band injection signatures (A03 / API8) ----

    /**
     * Backend error signatures that a resolver leaked an injected payload into a
     * SQL/NoSQL/OS sink. Kept distinct from [VERBOSE] so a hit is attributable to the
     * payload we sent (error-based injection) rather than generic stack-trace noise.
     */
    private val INJECTION_SIGNATURES: List<Pair<String, Regex>> = listOf(
        "SQLSTATE" to Regex("""(?i)SQLSTATE\[?"""),
        "Postgres syntax error" to Regex("""(?i)syntax error at or near"""),
        "MySQL syntax error" to Regex("""(?i)You have an error in your SQL syntax"""),
        "unterminated quoted string" to Regex("""(?i)unterminated quoted string"""),
        "quoted string not properly terminated" to Regex("""(?i)quoted string not properly terminated"""),
        "Oracle error" to Regex("""(?i)\bORA-\d{5}\b"""),
        "SQLite error" to Regex("""(?i)(SQLiteException|unrecognized token|SQL logic error)"""),
        "ODBC/SQL Server error" to Regex("""(?i)(Unclosed quotation mark|Microsoft SQL Server|ODBC SQL)"""),
        "MongoDB error" to Regex("""(?i)(MongoError|BSONError|E11000|unknown operator \$)"""),
        "command/path leak" to Regex("""(?i)(sh: .*: not found|/bin/sh:|cannot execute binary)"""),
        // additional dialects / drivers
        "PostgreSQL driver" to Regex("""(?i)(PG::\w+Error|org\.postgresql\.util\.PSQLException|pq: )"""),
        "MySQL driver" to Regex("""(?i)(com\.mysql\.jdbc|MySqlException|Warning.*mysqli?_|valid MySQL result)"""),
        "SQL Server driver" to Regex("""(?i)(System\.Data\.SqlClient\.SqlException|Incorrect syntax near|JDBC.*SQLServer)"""),
        "generic SQL error" to Regex("""(?i)(quoted string not properly terminated|unexpected end of SQL|near "[^"]*": syntax error)"""),
        "Mongo/NoSQL cast" to Regex("""(?i)(CastError|failed to parse|\${'$'}where|BadValue|Unsupported projection)"""),
    )

    /** Named backend injection-error signatures present in [body] (empty when none). */
    fun injectionSignatures(body: String): List<String> =
        INJECTION_SIGNATURES.filter { it.second.containsMatchIn(body) }.map { it.first }

    /**
     * True when [body] contains [needle], indicating the server evaluated an injected
     * arithmetic/template expression (e.g. `7*191` → `1337`) — template injection (SSTI) or
     * expression-evaluation reflection. The caller confirms it is evaluation, not an echo.
     */
    fun evaluatedExpression(body: String, needle: String = "1337"): Boolean = body.contains(needle)

    /** Markers that a path-traversal payload read a system file (LFI): /etc/passwd or win.ini. */
    private val FILE_READ: List<Pair<String, Regex>> = listOf(
        "/etc/passwd" to Regex("""root:.*?:0:0:"""),
        "win.ini" to Regex("""(?i)(\[fonts\]|\[extensions\]|for 16-bit app support)"""),
    )

    /** Named local-file-read markers present in [body] (empty when none) — path-traversal confirmation. */
    fun fileReadSignatures(body: String): List<String> =
        FILE_READ.filter { it.second.containsMatchIn(body) }.map { it.first }

    /**
     * Time-based blind signal: the injected sleep made this response at least [thresholdMs]
     * slower than the operation's baseline. Pure so it is unit-testable without real latency.
     */
    fun timeBlindFired(baselineMs: Long, payloadMs: Long, thresholdMs: Long = 4000): Boolean =
        payloadMs - baselineMs >= thresholdMs

    /**
     * Boolean-based blind signal: a TRUE tautology and a FALSE contradiction produced different
     * outcomes — one errored and the other didn't, or TRUE returned data while FALSE did not.
     * Conservative (reports only the differential, never dumped data). Pure/JSON-free so it is
     * testable; the finding tells the operator to confirm.
     */
    fun booleanBlindDiffers(trueBody: String, falseBody: String): Boolean {
        val tErr = trueBody.contains("\"errors\"")
        val fErr = falseBody.contains("\"errors\"")
        if (tErr != fErr) return true
        return dataNonNull(trueBody) && !dataNonNull(falseBody)
    }

    private val DATA_NULL = Regex("""(?i)"data"\s*:\s*null""")
    private fun dataNonNull(body: String): Boolean =
        body.contains("\"data\"") && !DATA_NULL.containsMatchIn(body)
}
