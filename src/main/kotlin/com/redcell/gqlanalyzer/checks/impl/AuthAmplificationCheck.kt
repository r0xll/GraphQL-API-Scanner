package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * API2:2023 — authentication brute-force amplification surface. SCHEMA-STATIC: flags
 * authentication-sensitive operations (login/verifyOtp/resetPassword/token/…) that
 * take credential arguments. GraphQL aliasing/array-batching lets an attacker pack N
 * attempts into one HTTP request (CrackQL-style), bypassing per-request rate limits.
 *
 * This check does NOT execute the auth operations (no credential spray — honoring the
 * no-mutation-on-enumerate guardrail). To demonstrate, select the operation in the
 * Operations grid and scan it; keep attempts dummy and capped.
 */
class AuthAmplificationCheck : GraphQLCheck {
    override val id = "auth-amplification"
    override val owaspId = "API2:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val authFields = (schema.queries() + schema.mutations())
            .filter { Heuristics.isAuthField(it.name) && it.args.isNotEmpty() }
            .map { it.name }
            .distinct()
        if (authFields.isEmpty()) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL auth operations batchable (rate-limit bypass surface)",
                detail = """
                    Authentication-sensitive operations accept credential arguments and are reachable
                    for aliasing/array batching: ${authFields.joinToString(", ")}.
                    If rate limiting and anti-automation are enforced per HTTP request rather than per
                    operation, an attacker can pack many login/OTP/reset attempts into a single request
                    (CrackQL-style), amplifying credential-stuffing and OTP brute force N× per request.

                    Detected statically; no credentials were submitted. Validate with a small, dummy,
                    capped alias batch against a test account per your ROE.

                    CVSS v3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (6.5, Medium) as an amplifier for
                    authentication attacks; impact depends on credential/OTP policy.
                """.trimIndent(),
                severity = Severity.MEDIUM,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Rate-limit and apply anti-automation (CAPTCHA, lockout, exponential backoff) at the
                    operation level, counting every aliased/batched operation. Cap batch size and alias
                    counts, and treat authentication fields as especially sensitive.
                """.trimIndent(),
            ),
        )
    }
}
