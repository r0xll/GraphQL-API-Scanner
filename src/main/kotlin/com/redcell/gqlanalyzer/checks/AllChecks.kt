package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.BatchingCheck
import com.redcell.gqlanalyzer.checks.impl.CsrfCheck
import com.redcell.gqlanalyzer.checks.impl.IntrospectionCheck

/** Central registry of every implemented check. Later phases append here. */
object AllChecks {
    fun list(): List<GraphQLCheck> = listOf(
        IntrospectionCheck(),
        CsrfCheck(),
        BatchingCheck(),
    )
}
