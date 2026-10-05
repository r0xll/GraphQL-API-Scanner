package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
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
import com.redcell.gqlanalyzer.transport.BurpOobClient
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.GraphQLResponses
import com.redcell.gqlanalyzer.transport.InjectionPayloads
import com.redcell.gqlanalyzer.transport.OobClient
import com.redcell.gqlanalyzer.transport.OobScanner
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
    /** Proof-level cap on how many injectable leaf positions per operation get an injection probe. */
    private val maxInjectionPoints: Int = 10,
    /** Collaborator client factory for the OOB confirmation pass (no-op when unavailable). */
    private val oobFactory: (MontoyaApi) -> OobClient = ::BurpOobClient,
    private val pollAttempts: Int = 6,
    private val pollDelayMs: Long = 2000,
) {

    data class ScanResult(
        val statuses: Map<Operation, OperationStatus>,
        val findings: List<Finding>,
        /** The final (post-adaptive) request/response per operation, for seeding the editor. */
        val probes: Map<Operation, OpProbe> = emptyMap(),
    )

    /** The exact request/response the scanner last sent for an operation. */
    data class OpProbe(val requestResponse: HttpRequestResponse, val body: String)

    private data class OobTargetMeta(val op: Operation, val loc: String, val path: List<String>, val ssrf: Boolean)

    fun scan(ctx: CheckContext, operations: List<Operation>): ScanResult {
        val schema = ctx.schema
        val statuses = LinkedHashMap<Operation, OperationStatus>()
        val findings = mutableListOf<Finding>()
        val probes = LinkedHashMap<Operation, OpProbe>()

        // Collaborator pass is minted once per scan; no-op when unavailable.
        val oob = oobFactory(ctx.api)
        val oobEnabled = schema != null && runCatching { oob.available() }.getOrDefault(false)
        val oobTargets = mutableListOf<OobScanner.Target>()
        val oobMeta = LinkedHashMap<String, OobTargetMeta>()

        for (op in operations) {
            val sensitive = if (schema != null) sensitiveLeaves(schema, op) else emptyList()
            val probe = adaptiveProbe(ctx, schema, op, sensitive)
            probes[op] = OpProbe(probe.rr, probe.body)

            val (status, opFindings) = scoreOperation(ctx, op, probe.rr, probe.body, sensitive)
            statuses[op] = status
            findings += opFindings

            // Active in-band injection on the operation's injectable leaves (incl. nested
            // input-object fields), reusing the values that satisfied validation. Selection
            // (this op is in the list) is the write gate, so mutations are probed only because
            // the operator ticked them. Attempted on every status — even INVALID_INPUT, since
            // each payload rides a request whose other required fields are valid.
            if (schema != null) {
                val loc = operationLocation(ctx, op)
                val paths = QueryBuilder.injectableLeafPaths(schema, op.field, maxPoints = maxInjectionPoints)
                findings += injectionFindings(ctx, schema, op, loc, paths, probe.overrides, probe.body, probe.elapsedMs)

                if (oobEnabled) {
                    for (path in paths) {
                        val key = "${op.parentTypeName}.${op.field.name}#${path.joinToString(".")}"
                        oobMeta[key] = OobTargetMeta(op, loc, path, Heuristics.isSsrfArg(path.last()))
                        oobTargets += OobScanner.Target(key) { host ->
                            send(ctx, QueryBuilder.injectedDocumentForPath(schema, op, path, QueryBuilder.literal("http://$host/"), probe.overrides))
                        }
                    }
                }
            }
        }

        // One out-of-band confirmation pass across every injectable leaf of the selected ops.
        if (oobTargets.isNotEmpty()) {
            val fired = OobScanner(oob, pollAttempts, pollDelayMs).run(oobTargets)
            for ((key, evidence) in fired) {
                val meta = oobMeta[key] ?: continue
                findings += oobFinding(meta, evidence)
            }
        }

        // Per-operation locations keep issues distinct; dedupe like CheckEngine.
        return ScanResult(statuses, findings.distinctBy { it.checkId to it.location }, probes)
    }

    private fun oobFinding(meta: OobTargetMeta, evidence: HttpRequestResponse): Finding {
        val label = meta.path.joinToString(".")
        val opName = "${meta.op.parentTypeName}.${meta.op.field.name}"
        val point = "$opName / $label"
        return if (meta.ssrf) {
            Finding(
                name = "Confirmed SSRF on '$label' in '${meta.op.field.name}' (out-of-band)",
                detail = "A unique Burp Collaborator URL placed at `$point` triggered an out-of-band " +
                    "interaction — the server fetches attacker-controlled URLs (SSRF). Observed, not inferred.\n" +
                    "Per ROE, pivot to internal targets (169.254.169.254, 127.0.0.1, internal hosts) for impact.\n\n" +
                    "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2, High); adjust to context.",
                severity = Severity.HIGH,
                confidence = Confidence.CERTAIN,
                remediation = "Allow-list outbound URLs (scheme/host), block link-local/loopback/metadata, " +
                    "pin resolved IPs, and disable redirects on server-side fetches.",
                evidence = listOf(evidence),
                checkId = "op-ssrf-confirmed",
                owaspId = "API7:2023",
                location = "${meta.loc}($label)",
                affectedOperation = opName,
            )
        } else {
            Finding(
                name = "Confirmed out-of-band dereference on '$label' in '${meta.op.field.name}'",
                detail = "A canary Collaborator URL placed at `$point` caused an out-of-band interaction from " +
                    "the server, though the field is not obviously URL-shaped — the backend dereferences " +
                    "attacker-controlled input (SSRF via an internal client, blind SSTI/XXE, or a URL-consuming " +
                    "downstream call). Confirm the sink and impact.\n\n" +
                    "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N (8.2, High) baseline; adjust to the sink.",
                severity = Severity.HIGH,
                confidence = Confidence.CERTAIN,
                remediation = "Treat argument values as untrusted: do not pass them to URL fetchers, template " +
                    "engines, or XML parsers without validation/allow-listing; disable external entity resolution.",
                evidence = listOf(evidence),
                checkId = "op-oob-confirmed",
                owaspId = "API7:2023",
                location = "${meta.loc}($label)",
                affectedOperation = opName,
            )
        }
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

    private data class Probe(val rr: HttpRequestResponse, val body: String, val overrides: Map<String, String>, val elapsedMs: Long)

    /**
     * Send the operation, and while the server rejects a generated argument with a
     * scalar/input coercion error, feed that error back in to synthesize a satisfying
     * value and retry — bounded by [maxInputRetries], never a large loop. The final
     * [Probe.overrides] are the arg values that satisfied validation, reused by the
     * injection pass so payloads ride an otherwise-valid request; [Probe.elapsedMs] is the
     * final send's latency, the baseline for time-based blind detection.
     */
    private fun adaptiveProbe(ctx: CheckContext, schema: SchemaModel?, op: Operation, sensitive: List<String>): Probe {
        var overrides = emptyMap<String, String>()
        var (rr, elapsed) = sendTimed(ctx, buildDoc(schema, op, sensitive, overrides))
        var body = rr.response()?.bodyToString().orEmpty()

        var tries = 0
        while (schema != null && tries < maxInputRetries &&
            Heuristics.isInputCoercionError(body) && !GraphQLHttp.hasData(body)
        ) {
            val fixes = coercionFixes(op, body)
            if (fixes.isEmpty() || overrides.entries.containsAll(fixes.entries)) break // no new progress
            overrides = overrides + fixes
            val timed = sendTimed(ctx, buildDoc(schema, op, sensitive, overrides))
            rr = timed.first; elapsed = timed.second
            body = rr.response()?.bodyToString().orEmpty()
            tries++
        }
        return Probe(rr, body, overrides, elapsed)
    }

    private fun send(ctx: CheckContext, doc: String): HttpRequestResponse =
        GraphQLHttp.postJson(ctx.api, ctx.request, GraphQLHttp.queryEnvelope(doc), ctx.config.authHeadersA)

    /** Send and measure wall-clock latency in ms (for time-based blind detection). */
    private fun sendTimed(ctx: CheckContext, doc: String): Pair<HttpRequestResponse, Long> {
        val start = System.nanoTime()
        val rr = send(ctx, doc)
        return rr to ((System.nanoTime() - start) / 1_000_000)
    }

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

    /** Accumulates which leaf paths fired a given technique, plus evidence + extra tokens. */
    private class TechniqueHits {
        val paths = linkedSetOf<String>()
        val tokens = linkedSetOf<String>()
        val evidence = mutableListOf<HttpRequestResponse>()
        fun isEmpty() = paths.isEmpty()
    }

    /**
     * Active in-band injection on the operation's injectable (string-backed scalar) leaves —
     * including fields **nested inside input-object arguments** (e.g. `event.profileId`). For each
     * leaf it rides the [InjectionPayloads] catalog on an otherwise-valid request (siblings kept
     * valid; top-level scalar args reuse the adaptive [workingOverrides]) and reads the response
     * per technique, baseline-subtracted: error signatures (SQL/NoSQL), SSTI evaluation (1337),
     * local-file-read markers, time-based blind (latency vs [baselineMs]), boolean-based blind
     * (TRUE/FALSE differential). Findings aggregate one per technique per op, labelled by path.
     *
     * Proof-level: ≤[maxInjectionPoints] leaves; once a technique fires for a leaf its remaining
     * variants are skipped (bounds sends and avoids repeated sleeps); blind techniques stay benign.
     */
    private fun injectionFindings(
        ctx: CheckContext,
        schema: SchemaModel,
        op: Operation,
        loc: String,
        paths: List<List<String>>,
        workingOverrides: Map<String, String>,
        baselineBody: String,
        baselineMs: Long,
    ): List<Finding> {
        if (paths.isEmpty()) return emptyList()

        val baseSigs = Heuristics.injectionSignatures(baselineBody).toSet()
        val baseFiles = Heuristics.fileReadSignatures(baselineBody).toSet()
        val baseEval = Heuristics.evaluatedExpression(baselineBody, InjectionPayloads.SSTI_RESULT)

        val error = TechniqueHits(); val ssti = TechniqueHits(); val file = TechniqueHits()
        val time = TechniqueHits(); val boolean = TechniqueHits()

        fun docFor(path: List<String>, value: String) =
            QueryBuilder.injectedDocumentForPath(schema, op, path, QueryBuilder.literal(value), workingOverrides)

        for (path in paths) {
            val label = path.joinToString(".")
            val fired = HashSet<InjectionPayloads.Technique>()
            var trueRr: HttpRequestResponse? = null
            var trueBody: String? = null

            for (p in InjectionPayloads.inBand) {
                // Once a family has confirmed for this leaf, skip its remaining variants.
                val family = when (p.technique) {
                    InjectionPayloads.Technique.BOOLEAN_TRUE, InjectionPayloads.Technique.BOOLEAN_FALSE -> InjectionPayloads.Technique.BOOLEAN_TRUE
                    else -> p.technique
                }
                if (family in fired) continue

                when (p.technique) {
                    InjectionPayloads.Technique.ERROR -> {
                        val rr = send(ctx, docFor(path, p.value))
                        val newSigs = Heuristics.injectionSignatures(rr.response()?.bodyToString().orEmpty()).filterNot { it in baseSigs }
                        if (newSigs.isNotEmpty()) { error.paths += label; error.tokens += newSigs; error.evidence += rr; fired += InjectionPayloads.Technique.ERROR }
                    }
                    InjectionPayloads.Technique.EVAL -> {
                        val rr = send(ctx, docFor(path, p.value))
                        if (!baseEval && Heuristics.evaluatedExpression(rr.response()?.bodyToString().orEmpty(), InjectionPayloads.SSTI_RESULT)) {
                            ssti.paths += label; ssti.evidence += rr; fired += InjectionPayloads.Technique.EVAL
                        }
                    }
                    InjectionPayloads.Technique.FILE -> {
                        val rr = send(ctx, docFor(path, p.value))
                        val newFiles = Heuristics.fileReadSignatures(rr.response()?.bodyToString().orEmpty()).filterNot { it in baseFiles }
                        if (newFiles.isNotEmpty()) { file.paths += label; file.tokens += newFiles; file.evidence += rr; fired += InjectionPayloads.Technique.FILE }
                    }
                    InjectionPayloads.Technique.TIME -> {
                        val (rr, ms) = sendTimed(ctx, docFor(path, p.value))
                        if (Heuristics.timeBlindFired(baselineMs, ms)) { time.paths += label; time.evidence += rr; fired += InjectionPayloads.Technique.TIME }
                    }
                    InjectionPayloads.Technique.BOOLEAN_TRUE -> {
                        trueRr = send(ctx, docFor(path, p.value)); trueBody = trueRr.response()?.bodyToString().orEmpty()
                    }
                    InjectionPayloads.Technique.BOOLEAN_FALSE -> {
                        val tb = trueBody ?: continue
                        val falseRr = send(ctx, docFor(path, p.value))
                        if (Heuristics.booleanBlindDiffers(tb, falseRr.response()?.bodyToString().orEmpty())) {
                            boolean.paths += label; trueRr?.let { boolean.evidence += it }; boolean.evidence += falseRr
                            fired += InjectionPayloads.Technique.BOOLEAN_TRUE
                        }
                    }
                }
            }
        }

        val opName = "${op.parentTypeName}.${op.field.name}"
        val out = mutableListOf<Finding>()
        fun at(h: TechniqueHits) = h.paths.joinToString(", ") { "`$it`" }

        if (!error.isEmpty()) out += Finding(
            name = "Error-based injection in '${op.field.name}' (at: ${error.paths.joinToString(", ")})",
            detail = "Injecting SQL/NoSQL breakers at ${at(error)} on `$opName` elicited backend errors absent " +
                "from the baseline: ${error.tokens.joinToString("; ")}. The field reaches an unparameterized " +
                "SQL/NoSQL sink (A03). Confirm/exploit with sqlmap via the injection-seeder scaffold.\n\n" +
                "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical); adjust to the sink.",
            severity = Severity.HIGH, confidence = Confidence.FIRM,
            remediation = "Parameterize queries; validate/canonicalize arguments; least-privilege DB accounts.",
            evidence = error.evidence.toList(), checkId = "op-injection-error", owaspId = "API8:2023",
            location = loc, affectedOperation = opName,
        )
        if (!ssti.isEmpty()) out += Finding(
            name = "Template/expression injection (SSTI) in '${op.field.name}' (at: ${ssti.paths.joinToString(", ")})",
            detail = "An arithmetic template payload (`7*191`) placed at ${at(ssti)} on `$opName` came back " +
                "evaluated to `${InjectionPayloads.SSTI_RESULT}` (absent from the baseline) — the backend evaluates " +
                "attacker-controlled input in a template/expression engine (SSTI → often RCE). Confirm the engine " +
                "before escalating.\n\nCVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical) if RCE.",
            severity = Severity.HIGH, confidence = Confidence.TENTATIVE,
            remediation = "Never interpolate user input into template/expression engines; use a sandboxed, " +
                "logic-less template with bound context values.",
            evidence = ssti.evidence.toList(), checkId = "op-injection-ssti", owaspId = "API8:2023",
            location = loc, affectedOperation = opName,
        )
        if (!file.isEmpty()) out += Finding(
            name = "Path traversal / local file read in '${op.field.name}' (at: ${file.paths.joinToString(", ")})",
            detail = "A path-traversal payload at ${at(file)} on `$opName` returned a system-file marker " +
                "(${file.tokens.joinToString("; ")}) — the field is used in a filesystem path without " +
                "canonicalization (LFI).\n\nCVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5, High); higher " +
                "if it reaches secrets or combines with upload.",
            severity = Severity.HIGH, confidence = Confidence.FIRM,
            remediation = "Resolve and canonicalize paths against an allow-listed base directory; reject `..` and " +
                "absolute paths; never pass user input straight to file APIs.",
            evidence = file.evidence.toList(), checkId = "op-injection-file", owaspId = "API8:2023",
            location = loc, affectedOperation = opName,
        )
        if (!time.isEmpty()) out += Finding(
            name = "Time-based blind SQLi in '${op.field.name}' (at: ${time.paths.joinToString(", ")})",
            detail = "A sleep payload at ${at(time)} on `$opName` delayed the response by at least ~5s over the " +
                "operation's baseline — the field reaches a SQL sink evaluating injected logic (blind SQLi). " +
                "Re-run to confirm the delay is reproducible.\n\n" +
                "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical); adjust to the sink.",
            severity = Severity.HIGH, confidence = Confidence.FIRM,
            remediation = "Parameterize queries; validate/canonicalize arguments; least-privilege DB accounts.",
            evidence = time.evidence.toList(), checkId = "op-injection-time", owaspId = "API8:2023",
            location = loc, affectedOperation = opName,
        )
        if (!boolean.isEmpty()) out += Finding(
            name = "Boolean-based blind SQLi in '${op.field.name}' (at: ${boolean.paths.joinToString(", ")})",
            detail = "A TRUE tautology and a FALSE contradiction at ${at(boolean)} on `$opName` produced different " +
                "outcomes (data/error differential) — the field reaches a SQL sink whose logic the input alters " +
                "(blind SQLi). Only the differential is reported; no data was exfiltrated.\n\n" +
                "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical); adjust to the sink.",
            severity = Severity.HIGH, confidence = Confidence.FIRM,
            remediation = "Parameterize queries; validate/canonicalize arguments; least-privilege DB accounts.",
            evidence = boolean.evidence.toList(), checkId = "op-injection-boolean", owaspId = "API8:2023",
            location = loc, affectedOperation = opName,
        )
        return out
    }

    /** Sensitive scalar/enum leaf fields on the operation's return object type. */
    private fun sensitiveLeaves(schema: SchemaModel, op: Operation): List<String> {
        val rt = schema.type(op.field.typeRef.namedType()) ?: return emptyList()
        return rt.fields.filter { Heuristics.isSensitiveField(it.name) }.map { it.name }
    }

    companion object {
        fun classify(body: String, field: String, status: Int): OperationStatus = when {
            Heuristics.containsAuthzError(body) -> OperationStatus.DENIED
            GraphQLResponses.fieldNonNull(body, field) -> OperationStatus.RESOLVED
            Heuristics.isInputCoercionError(body) -> OperationStatus.INVALID_INPUT
            GraphQLHttp.errorMessages(body).isEmpty() && status in 200..299 -> OperationStatus.EMPTY
            else -> OperationStatus.ERROR
        }
    }
}
