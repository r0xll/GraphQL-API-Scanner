package com.redcell.gqlanalyzer.engine

import burp.api.montoya.http.message.HttpRequestResponse
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.checks.impl.BflaCheck
import com.redcell.gqlanalyzer.checks.impl.BolaCheck
import com.redcell.gqlanalyzer.checks.impl.FieldAuthzCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.model.OperationStatus
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.schema.SchemaModel
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.GraphQLResponses
import com.redcell.gqlanalyzer.transport.QueryBuilder
import com.redcell.gqlanalyzer.transport.ScalarValues

/**
 * Crawls the selected operations like a Burp API scan: one primary probe per
 * operation (plus one extra for a two-identity BOLA comparison), classifying each
 * and emitting per-operation findings. Mutations/subscriptions reach here only
 * because the operator selected them — selection is the write-safety gate.
 */
class OperationScanner(
    /** Bounded adaptive retries to satisfy scalar/input validation per operation (proof-level). */
    private val maxInputRetries: Int = 3,
    /** Proof-level cap on how many injectable args per operation get an injection probe. */
    private val maxInjectableArgs: Int = 10,
) {

    data class ScanResult(
        val statuses: Map<Operation, OperationStatus>,
        val findings: List<Finding>,
        /** The final (post-adaptive) request/response per operation, for seeding the editor. */
        val probes: Map<Operation, OpProbe> = emptyMap(),
    )

    /** The exact request/response the scanner last sent for an operation. */
    data class OpProbe(val requestResponse: HttpRequestResponse, val body: String)

    fun scan(ctx: CheckContext, operations: List<Operation>): ScanResult {
        val schema = ctx.schema
        val statuses = LinkedHashMap<Operation, OperationStatus>()
        val findings = mutableListOf<Finding>()
        val probes = LinkedHashMap<Operation, OpProbe>()

        for (op in operations) {
            val sensitive = if (schema != null) sensitiveLeaves(schema, op) else emptyList()
            val probe = adaptiveProbe(ctx, schema, op, sensitive)
            probes[op] = OpProbe(probe.rr, probe.body)

            val (status, opFindings) = scoreOperation(ctx, op, probe.rr, probe.body, sensitive)
            statuses[op] = status
            findings += opFindings

            // Active in-band injection on the operation's own injectable args, reusing the
            // values that already satisfied validation. Selection (this op is in the list) is
            // the write gate, so mutations are probed only because the operator ticked them.
            if (schema != null && status != OperationStatus.INVALID_INPUT) {
                findings += injectionFindings(ctx, schema, op, operationLocation(ctx, op), probe.overrides, probe.body)
            }
        }

        // Per-operation locations keep issues distinct; dedupe like CheckEngine.
        return ScanResult(statuses, findings.distinctBy { it.checkId to it.location }, probes)
    }

    /**
     * Classify a single operation from an already-obtained response and run its
     * per-operation analyzers. Used by both the batch [scan] and the editor re-test.
     * [body] defaults to the response body of [rr] so callers that only have the
     * request/response (e.g. an edited manual re-send) need not extract it.
     */
    fun scoreOperation(
        ctx: CheckContext,
        op: Operation,
        rr: HttpRequestResponse,
        body: String = rr.response()?.bodyToString().orEmpty(),
        sensitive: List<String> = ctx.schema?.let { sensitiveLeaves(it, op) } ?: emptyList(),
    ): Pair<OperationStatus, List<Finding>> {
        val loc = operationLocation(ctx, op)
        val status = classify(body, op.field.name, rr.response()?.statusCode()?.toInt() ?: 0)
        val findings = operationFindings(ctx, op, loc, body, rr, sensitive)
        return status to findings
    }

    /** `url#Type.field` (or bare `Type.field` when the base URL is unavailable). */
    private fun operationLocation(ctx: CheckContext, op: Operation): String {
        val baseUrl = runCatching { ctx.request.url() }.getOrNull().orEmpty()
        val opLabel = "${op.parentTypeName}.${op.field.name}"
        return if (baseUrl.isEmpty()) opLabel else "$baseUrl#$opLabel"
    }

    private data class Probe(val rr: HttpRequestResponse, val body: String, val overrides: Map<String, String>)

    /**
     * Send the operation, and while the server rejects a generated argument with a
     * scalar/input coercion error, feed that error back in to synthesize a satisfying
     * value and retry — bounded by [maxInputRetries], never a large loop. The final
     * [Probe.overrides] are the arg values that satisfied validation, reused by the
     * injection pass so payloads ride an otherwise-valid request.
     */
    private fun adaptiveProbe(ctx: CheckContext, schema: SchemaModel?, op: Operation, sensitive: List<String>): Probe {
        var overrides = emptyMap<String, String>()
        var rr = send(ctx, buildDoc(schema, op, sensitive, overrides))
        var body = rr.response()?.bodyToString().orEmpty()

        var tries = 0
        while (schema != null && tries < maxInputRetries &&
            Heuristics.isInputCoercionError(body) && !GraphQLHttp.hasData(body)
        ) {
            val fixes = coercionFixes(op, body)
            if (fixes.isEmpty() || overrides.entries.containsAll(fixes.entries)) break // no new progress
            overrides = overrides + fixes
            rr = send(ctx, buildDoc(schema, op, sensitive, overrides))
            body = rr.response()?.bodyToString().orEmpty()
            tries++
        }
        return Probe(rr, body, overrides)
    }

    private fun send(ctx: CheckContext, doc: String): HttpRequestResponse =
        GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc), ctx.config.authHeadersA)

    /** arg name → synthesized literal, for args whose scalar type the response flagged as invalid. */
    private fun coercionFixes(op: Operation, body: String): Map<String, String> {
        val fixes = HashMap<String, String>()
        for (msg in GraphQLHttp.errorMessages(body)) {
            val type = Heuristics.coercionTypeName(msg) ?: continue
            val value = ScalarValues.synthesize(type, msg) ?: continue
            op.field.args.filter { it.typeRef.namedType() == type }.forEach { fixes[it.name] = value }
        }
        return fixes
    }

    private fun buildDoc(schema: SchemaModel?, op: Operation, sensitive: List<String>, overrides: Map<String, String> = emptyMap()): String {
        // No schema (reconstruction gave only names) -> bare field probe.
        if (schema == null) return "query { ${op.field.name} }"
        return QueryBuilder.operationDocument(schema, op, sensitive, overrides)
    }

    private fun operationFindings(
        ctx: CheckContext,
        op: Operation,
        loc: String,
        body: String,
        rr: HttpRequestResponse,
        sensitive: List<String>,
    ): List<Finding> {
        val out = mutableListOf<Finding>()
        val field = op.field.name

        // BFLA (API5): privileged-named operation authorized for identity A (query or mutation).
        if (Heuristics.isPrivilegedField(field) && BflaCheck.authorized(body, field)) {
            val mut = op.kind == com.redcell.gqlanalyzer.model.OperationKind.MUTATION
            out += Finding(
                name = "BFLA: privileged ${op.kind.name.lowercase()} '$field' authorized",
                detail = "The privileged-looking ${op.kind.name.lowercase()} `$field` returned data with no " +
                    "authorization error for the configured identity. Confirm that identity is unprivileged for it." +
                    (if (mut) " As a mutation, this is a privileged state-changing function reachable by a lower-privilege caller." else "") +
                    "\n\nCVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:${if (mut) "H" else "N"}/A:N (${if (mut) "8.1, High" else "6.5, Medium"}).",
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = "Enforce function-level authorization server-side (deny-by-default).",
                evidence = listOf(rr),
                checkId = "op-bfla",
                owaspId = "API5:2023",
                location = loc,
                affectedOperation = "${op.parentTypeName}.${op.field.name}",
            )
        }

        // Sensitive property exposure (API3): sensitive leaves returned non-null.
        if (sensitive.isNotEmpty()) {
            val exposed = FieldAuthzCheck.exposedFields(body, field, sensitive)
            if (exposed.isNotEmpty()) {
                out += Finding(
                    name = "Sensitive fields exposed by '$field' (${exposed.joinToString(", ")})",
                    detail = "Operation `$field` returned sensitive field(s) ${exposed.joinToString(", ")} " +
                        "to the caller — missing property-level authorization.\n\n" +
                        "CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium).",
                    severity = Severity.HIGH,
                    confidence = Confidence.FIRM,
                    remediation = "Resolve sensitive fields only for authorized principals, or remove them from the graph.",
                    evidence = listOf(rr),
                    checkId = "op-field-authz",
                    owaspId = "API3:2023",
                    location = loc,
                    affectedOperation = "${op.parentTypeName}.${op.field.name}",
                )
            }
        }

        // Verbose errors (API8) tagged to this operation.
        val indicators = Heuristics.verboseIndicators(body)
        if (indicators.isNotEmpty()) {
            out += Finding(
                name = "Verbose error from '$field'",
                detail = "Probing `$field` leaked internal details: ${indicators.joinToString("; ")}.\n\n" +
                    "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N (5.3, Medium).",
                severity = Severity.MEDIUM,
                confidence = Confidence.FIRM,
                remediation = "Return generic errors in production; strip stack traces from responses.",
                evidence = listOf(rr),
                checkId = "op-verbose-errors",
                owaspId = "API8:2023",
                location = loc,
                affectedOperation = "${op.parentTypeName}.${op.field.name}",
            )
        }

        // BOLA (API1): id-addressed, single-required-arg operation accessible across two identities.
        bolaFinding(ctx, op, loc, body, rr)?.let { out += it }

        return out
    }

    private fun bolaFinding(
        ctx: CheckContext,
        op: Operation,
        loc: String,
        primaryBody: String,
        primaryRr: HttpRequestResponse,
    ): Finding? {
        if (!ctx.config.hasTwoIdentities) return null
        val schema = ctx.schema ?: return null
        val idArg = op.field.args.firstOrNull { it.name.lowercase() in SchemaModel.ID_ARG_NAMES } ?: return null
        // Only when the id arg is the sole required arg, so a single-arg query is valid.
        if (op.field.args.any { it.typeRef.isNonNull() && it != idArg }) return null

        val id = ctx.config.knownObjectId ?: "1"
        val bolaDoc = QueryBuilder.singleArgQuery(schema, op.field, idArg.name, id)

        // identity A is the primary probe only if it used the same single-arg doc; re-send to be safe.
        val aRr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(bolaDoc), ctx.config.authHeadersA)
        val bRr = GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(bolaDoc), ctx.config.authHeadersB)
        val aBody = aRr.response()?.bodyToString().orEmpty()
        val bBody = bRr.response()?.bodyToString().orEmpty()

        val verdict = BolaCheck.decide(aBody, bBody, op.field.name, knownOwnership = ctx.config.knownObjectId != null)
            ?: return null

        return Finding(
            name = "Potential BOLA on '${op.field.name}' (cross-identity object access)",
            detail = "${verdict.detail}\nTarget: `${op.field.name}(${idArg.name}: ${QueryBuilder.literal(id)})`.\n\n" +
                "CVSS v3.1: AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N (6.5, Medium); higher if enumerable or mutable.",
            severity = Severity.HIGH,
            confidence = verdict.confidence,
            remediation = "Enforce object-level authorization in the resolver; prefer unguessable ids.",
            evidence = listOf(aRr, bRr),
            checkId = "op-bola",
            owaspId = "API1:2023",
            location = loc,
            affectedOperation = "${op.parentTypeName}.${op.field.name}",
        )
    }

    /**
     * Active in-band injection on the operation's own injectable (string-backed scalar)
     * arguments. For each arg it rides a payload on an otherwise-valid request (reusing the
     * adaptive [workingOverrides]) and compares the response against the operation's own
     * baseline ([baselineBody], the adaptive probe's final response): a *new* backend error
     * signature ⇒ error-based SQL/NoSQL injection, `${7*7}` newly evaluating to `49` ⇒ SSTI.
     * Results aggregate into at most one error finding and one SSTI finding per operation.
     *
     * Proof-level: at most [maxInjectableArgs] args, ≤2 sends per arg, benign payloads only.
     */
    private fun injectionFindings(
        ctx: CheckContext,
        schema: SchemaModel,
        op: Operation,
        loc: String,
        workingOverrides: Map<String, String>,
        baselineBody: String,
    ): List<Finding> {
        val injectable = op.field.args
            .filter { Heuristics.isInjectableScalar(schema, it.typeRef) }
            .take(maxInjectableArgs)
        if (injectable.isEmpty()) return emptyList()

        val baselineSigs = Heuristics.injectionSignatures(baselineBody).toSet()
        val baselineHad49 = Heuristics.evaluatedExpression(baselineBody, SSTI_RESULT)

        val errorArgs = linkedSetOf<String>()
        val errorSigs = linkedSetOf<String>()
        val sstiArgs = linkedSetOf<String>()
        val evidence = mutableListOf<HttpRequestResponse>()

        for (arg in injectable) {
            val sqlRr = send(ctx, QueryBuilder.injectedOperationDocument(schema, op, arg.name, QueryBuilder.literal(SQL_PAYLOAD), workingOverrides))
            val newSigs = Heuristics.injectionSignatures(sqlRr.response()?.bodyToString().orEmpty()).filterNot { it in baselineSigs }
            if (newSigs.isNotEmpty()) {
                errorArgs += arg.name
                errorSigs += newSigs
                evidence += sqlRr
            }

            if (!baselineHad49) {
                val sstiRr = send(ctx, QueryBuilder.injectedOperationDocument(schema, op, arg.name, QueryBuilder.literal(SSTI_PAYLOAD), workingOverrides))
                if (Heuristics.evaluatedExpression(sstiRr.response()?.bodyToString().orEmpty(), SSTI_RESULT)) {
                    sstiArgs += arg.name
                    evidence += sstiRr
                }
            }
        }

        val out = mutableListOf<Finding>()
        val opName = "${op.parentTypeName}.${op.field.name}"
        if (errorArgs.isNotEmpty()) {
            out += Finding(
                name = "Error-based injection in '${op.field.name}' (arg: ${errorArgs.joinToString(", ")})",
                detail = "Injecting a single quote into ${errorArgs.joinToString(", ") { "`$it`" }} on `$opName` " +
                    "elicited a backend error not present in the operation's baseline response: " +
                    "${errorSigs.joinToString("; ")}. The argument reaches an unparameterized SQL/NoSQL sink " +
                    "(A03 Injection). Confirm/exploit with sqlmap using the injection-seeder scaffold.\n\n" +
                    "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical) baseline for SQLi; adjust to the sink.",
                severity = Severity.HIGH,
                confidence = Confidence.FIRM,
                remediation = "Use parameterized queries / prepared statements in the resolver; validate and " +
                    "canonicalize argument values; apply least-privilege DB accounts.",
                evidence = evidence.toList(),
                checkId = "op-injection-error",
                owaspId = "API8:2023",
                location = loc,
                affectedOperation = opName,
            )
        }
        if (sstiArgs.isNotEmpty()) {
            out += Finding(
                name = "Template/expression injection (SSTI) in '${op.field.name}' (arg: ${sstiArgs.joinToString(", ")})",
                detail = "The payload `\${7*7}` placed in ${sstiArgs.joinToString(", ") { "`$it`" }} on `$opName` came " +
                    "back evaluated to `49` (absent from the baseline), so the backend evaluates attacker-controlled " +
                    "input in a template/expression engine (SSTI → often RCE). Confirm the engine and that `49` is " +
                    "evaluation rather than coincidental reflection before escalating.\n\n" +
                    "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical) if it proves to be RCE.",
                severity = Severity.HIGH,
                confidence = Confidence.TENTATIVE,
                remediation = "Never interpolate user input into template/expression engines; use a sandboxed, " +
                    "logic-less template and pass data as bound context values.",
                evidence = evidence.toList(),
                checkId = "op-injection-ssti",
                owaspId = "API8:2023",
                location = loc,
                affectedOperation = opName,
            )
        }
        return out
    }

    /** Sensitive scalar/enum leaf fields on the operation's return object type. */
    private fun sensitiveLeaves(schema: SchemaModel, op: Operation): List<String> {
        val rt = schema.type(op.field.typeRef.namedType()) ?: return emptyList()
        return rt.fields.filter { Heuristics.isSensitiveField(it.name) }.map { it.name }
    }

    companion object {
        private const val SQL_PAYLOAD = "'"
        private const val SSTI_PAYLOAD = "\${7*7}"
        private const val SSTI_RESULT = "49"

        fun classify(body: String, field: String, status: Int): OperationStatus = when {
            Heuristics.containsAuthzError(body) -> OperationStatus.DENIED
            GraphQLResponses.fieldNonNull(body, field) -> OperationStatus.RESOLVED
            Heuristics.isInputCoercionError(body) -> OperationStatus.INVALID_INPUT
            GraphQLHttp.errorMessages(body).isEmpty() && status in 200..299 -> OperationStatus.EMPTY
            else -> OperationStatus.ERROR
        }
    }
}
