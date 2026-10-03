package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity
import com.redcell.gqlanalyzer.transport.GraphQLHttp
import com.redcell.gqlanalyzer.transport.QueryBuilder

/**
 * Active **in-band** injection probe (A03 Injection; filed under API8:2023). Places a
 * tiny benign payload set into String/ID arguments on **read-only root query fields**
 * and looks for two in-band signals, each compared against a clean baseline probe so the
 * hit is attributable to the payload:
 *
 *  - a backend injection error signature (SQLSTATE / SQL syntax / Oracle / Mongo / …) that
 *    the baseline did not produce  ⇒ error-based SQL/NoSQL injection (FIRM);
 *  - the server evaluating `${7*7}` to `49` when the baseline did not  ⇒ template injection
 *    / expression evaluation (SSTI, TENTATIVE — confirm it is evaluation, not coincidence).
 *
 * Proof-level and non-destructive: query-root reads only (never a mutation/subscription),
 * capped at [maxPoints] insertion points, ≤3 sends per point (baseline + 2 payloads), benign
 * payloads only (a single quote and an arithmetic expression) — no boolean-blind data
 * tampering, no stacked/destructive SQL, no OS command execution. Complements the static
 * `InjectionSeederCheck` (lists points, sends nothing) and the Collaborator-gated
 * `OobCanaryInjectionCheck` (blind, out-of-band).
 */
class ActiveInjectionCheck(
    private val maxPoints: Int = 20,
) : GraphQLCheck {
    override val id = "active-injection"
    override val owaspId = "API8:2023"

    private companion object {
        const val SQL_PAYLOAD = "'"
        const val SSTI_PAYLOAD = "\${7*7}"
        const val SSTI_RESULT = "49"
        const val BASELINE = "gqlanalyzerbaseline"
    }

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val queryType = schema.queryType() ?: return emptyList()

        // String/ID args on root query fields only — never inject into mutations/subscriptions.
        val points = Heuristics.injectionInsertionPoints(schema)
            .filter { it.parentType == queryType.name }
            .take(maxPoints)
        if (points.isEmpty()) return emptyList()

        val url = runCatching { ctx.request.url() }.getOrNull().orEmpty()
        val out = mutableListOf<Finding>()

        for (p in points) {
            val field = queryType.fields.firstOrNull { it.name == p.field } ?: continue
            val label = "${p.parentType}.${p.field}(${p.arg})"
            val loc = if (url.isEmpty()) label else "$url#${p.parentType}.${p.field}"

            // Baseline: a benign value in the same argument, to subtract pre-existing signals.
            val baseBody = send(ctx, schema, field, p.arg, BASELINE)
            val baseSigs = Heuristics.injectionSignatures(baseBody).toSet()
            val baseHad49 = Heuristics.evaluatedExpression(baseBody, SSTI_RESULT)

            // Error-based: a single quote should break an unparameterized query.
            val sqlRr = sendRr(ctx, schema, field, p.arg, SQL_PAYLOAD)
            val sqlBody = sqlRr.response()?.bodyToString().orEmpty()
            val newSigs = Heuristics.injectionSignatures(sqlBody).filterNot { it in baseSigs }
            if (newSigs.isNotEmpty()) {
                out += Finding(
                    name = "Error-based injection on $label (${newSigs.joinToString(", ")})",
                    detail = "Injecting a single quote into `$label` elicited a backend error not present in a " +
                        "baseline request: ${newSigs.joinToString("; ")}. The argument reaches an " +
                        "unparameterized SQL/NoSQL sink (A03 Injection). Confirm with sqlmap using the scaffold " +
                        "from the injection-seeder finding.\n\n" +
                        "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical) baseline for SQLi; " +
                        "adjust to the sink and data reachable.",
                    severity = Severity.HIGH,
                    confidence = Confidence.FIRM,
                    remediation = "Use parameterized queries / prepared statements in the resolver; validate and " +
                        "canonicalize argument values; apply least-privilege DB accounts.",
                    evidence = listOf(sqlRr),
                    checkId = "active-injection-error",
                    owaspId = owaspId,
                    location = loc,
                    affectedOperation = "${p.parentType}.${p.field}",
                )
            }

            // SSTI / expression evaluation: ${7*7} -> 49 when the baseline had no 49.
            if (!baseHad49) {
                val sstiRr = sendRr(ctx, schema, field, p.arg, SSTI_PAYLOAD)
                val sstiBody = sstiRr.response()?.bodyToString().orEmpty()
                if (Heuristics.evaluatedExpression(sstiBody, SSTI_RESULT)) {
                    out += Finding(
                        name = "Template/expression injection (SSTI) on $label",
                        detail = "The payload `\${7*7}` placed in `$label` came back evaluated to `49` " +
                            "(absent from the baseline), so the backend is evaluating attacker-controlled input in a " +
                            "template or expression engine (SSTI → often RCE). Confirm the engine and that `49` is " +
                            "evaluation rather than coincidental reflection before escalating.\n\n" +
                            "CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8, Critical) if it proves to be RCE.",
                        severity = Severity.HIGH,
                        confidence = Confidence.TENTATIVE,
                        remediation = "Never interpolate user input into template/expression engines; use a sandboxed, " +
                            "logic-less template and pass data as bound context values.",
                        evidence = listOf(sstiRr),
                        checkId = "active-injection-ssti",
                        owaspId = owaspId,
                        location = loc,
                        affectedOperation = "${p.parentType}.${p.field}",
                    )
                }
            }
        }
        return out
    }

    private fun sendRr(
        ctx: CheckContext,
        schema: com.redcell.gqlanalyzer.schema.SchemaModel,
        field: com.redcell.gqlanalyzer.schema.GqlField,
        arg: String,
        value: String,
    ) = GraphQLHttp.postJson(
        ctx.api, ctx.request,
        GraphQLHttp.queryEnvelope(QueryBuilder.injectedQuery(schema, field, arg, value)),
    )

    private fun send(
        ctx: CheckContext,
        schema: com.redcell.gqlanalyzer.schema.SchemaModel,
        field: com.redcell.gqlanalyzer.schema.GqlField,
        arg: String,
        value: String,
    ) = sendRr(ctx, schema, field, arg, value).response()?.bodyToString().orEmpty()
}
