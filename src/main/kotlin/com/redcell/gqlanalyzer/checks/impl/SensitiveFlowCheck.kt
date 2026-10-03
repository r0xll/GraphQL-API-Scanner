package com.redcell.gqlanalyzer.checks.impl

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.checks.Heuristics
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Confidence
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Severity

/**
 * API6:2023 (Unrestricted Access to Sensitive Business Flows). SCHEMA-STATIC: flags
 * mutations whose names drive high-value business flows (purchase, transfer, refund,
 * payout, invite, grant, delete, …) for manual review. Whether these flows have
 * anti-automation / rate / fraud controls is business-logic — surfaced here as
 * review targets, never exercised. Sends nothing.
 */
class SensitiveFlowCheck : GraphQLCheck {
    override val id = "sensitive-flow"
    override val owaspId = "API6:2023"

    override fun run(ctx: CheckContext): List<Finding> {
        val schema = ctx.schema ?: return emptyList()
        val flows = schema.mutations().map { it.name }.filter { Heuristics.isSensitiveFlow(it) }.distinct()
        if (flows.isEmpty()) return emptyList()

        return listOf(
            Finding(
                name = "GraphQL sensitive business flows exposed (${flows.size})",
                detail = """
                    Mutations driving high-value business flows are exposed and warrant manual review
                    for unrestricted access (API6): ${flows.joinToString(", ")}.
                    Confirm each enforces anti-automation (rate limiting, CAPTCHA, device/velocity
                    checks), server-side authorization, and business invariants (e.g. balance/ownership
                    checks) — not just input validation.

                    Detected statically from the schema; no mutation was invoked.

                    CVSS v3.1: not scored — business-logic review guidance; impact depends on the flow
                    (payment/transfer/role-change are typically High).
                """.trimIndent(),
                severity = Severity.INFORMATION,
                confidence = Confidence.TENTATIVE,
                remediation = """
                    Protect sensitive flows with anti-automation and abuse controls (rate/velocity
                    limits, CAPTCHA/step-up where appropriate), enforce authorization and business
                    invariants server-side, and monitor for anomalous volumes per principal.
                """.trimIndent(),
            ),
        )
    }
}
