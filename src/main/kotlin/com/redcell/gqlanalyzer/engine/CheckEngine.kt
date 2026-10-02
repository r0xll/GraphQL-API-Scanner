package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.checks.GraphQLCheck
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Finding

/**
 * Fans each registered check out over a [CheckContext], stamps provenance
 * (checkId/owaspId/location) onto findings, and de-duplicates by
 * (checkId, location). A check that throws is isolated — logged, not fatal.
 */
class CheckEngine(private val checks: List<GraphQLCheck>) {

    fun run(ctx: CheckContext): List<Finding> {
        val location = runCatching { ctx.request.url() }.getOrNull().orEmpty()
        val collected = checks.flatMap { check ->
            runCatching { check.run(ctx) }
                .onFailure { ctx.api.logging().logToError("Check '${check.id}' failed: ${it.message}") }
                .getOrDefault(emptyList())
                .map { f ->
                    f.copy(
                        checkId = check.id,
                        owaspId = check.owaspId,
                        location = f.location.ifEmpty { location },
                    )
                }
        }
        // Dedupe by (checkId, location) per spec.
        return collected.distinctBy { it.checkId to it.location }
    }

    companion object {
        /** All checks available to the engine. Phases 2-3 populate this. */
        fun defaultChecks(): List<GraphQLCheck> = com.redcell.gqlanalyzer.checks.AllChecks.list()
    }
}
