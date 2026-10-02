package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Finding

/**
 * One OWASP API Top 10 (2023) check. Implementations MUST stay proof-level:
 * never DoS, never persist privileged mutations, never exceed the batch cap.
 */
interface GraphQLCheck {
    /** Stable, unique identifier, e.g. "introspection". */
    val id: String

    /** OWASP API risk id, e.g. "API9:2023". */
    val owaspId: String

    fun run(ctx: CheckContext): List<Finding>
}
