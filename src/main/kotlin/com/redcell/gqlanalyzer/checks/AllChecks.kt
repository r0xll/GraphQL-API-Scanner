package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.BatchingCheck
import com.redcell.gqlanalyzer.checks.impl.BflaCheck
import com.redcell.gqlanalyzer.checks.impl.BolaCheck
import com.redcell.gqlanalyzer.checks.impl.ContentTypeBypassCheck
import com.redcell.gqlanalyzer.checks.impl.CsrfCheck
import com.redcell.gqlanalyzer.checks.impl.DepthComplexityCheck
import com.redcell.gqlanalyzer.checks.impl.DirectiveOverloadCheck
import com.redcell.gqlanalyzer.checks.impl.FieldAuthzCheck
import com.redcell.gqlanalyzer.checks.impl.FieldSuggestionCheck
import com.redcell.gqlanalyzer.checks.impl.GraphiqlExposedCheck
import com.redcell.gqlanalyzer.checks.impl.InjectionSeederCheck
import com.redcell.gqlanalyzer.checks.impl.IntrospectionCheck
import com.redcell.gqlanalyzer.checks.impl.MassAssignmentCheck
import com.redcell.gqlanalyzer.checks.impl.SsrfSeederCheck
import com.redcell.gqlanalyzer.checks.impl.VerboseErrorCheck

/** Central registry of every implemented check. */
object AllChecks {
    fun list(): List<GraphQLCheck> = listOf(
        // Phase 2
        IntrospectionCheck(),
        CsrfCheck(),
        BatchingCheck(),
        // Phase 3
        FieldSuggestionCheck(),
        FieldAuthzCheck(),
        BolaCheck(),
        BflaCheck(),
        MassAssignmentCheck(),
        DepthComplexityCheck(),
        VerboseErrorCheck(),
        InjectionSeederCheck(),
        // v0.3.0
        SsrfSeederCheck(),
        GraphiqlExposedCheck(),
        ContentTypeBypassCheck(),
        DirectiveOverloadCheck(),
    )
}
