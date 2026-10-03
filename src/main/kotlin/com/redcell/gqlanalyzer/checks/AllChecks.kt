package com.redcell.gqlanalyzer.checks

import com.redcell.gqlanalyzer.checks.impl.ActiveInjectionCheck
import com.redcell.gqlanalyzer.checks.impl.ActiveSsrfCheck
import com.redcell.gqlanalyzer.checks.impl.AltIntrospectionCheck
import com.redcell.gqlanalyzer.checks.impl.ApqDetectionCheck
import com.redcell.gqlanalyzer.checks.impl.AuthAmplificationCheck
import com.redcell.gqlanalyzer.checks.impl.BatchingCheck
import com.redcell.gqlanalyzer.checks.impl.BflaCheck
import com.redcell.gqlanalyzer.checks.impl.BolaCheck
import com.redcell.gqlanalyzer.checks.impl.CircularFragmentCheck
import com.redcell.gqlanalyzer.checks.impl.ContentTypeBypassCheck
import com.redcell.gqlanalyzer.checks.impl.CorsCheck
import com.redcell.gqlanalyzer.checks.impl.CsrfCheck
import com.redcell.gqlanalyzer.checks.impl.CswshCheck
import com.redcell.gqlanalyzer.checks.impl.DeferStreamCheck
import com.redcell.gqlanalyzer.checks.impl.DeprecatedFieldInventoryCheck
import com.redcell.gqlanalyzer.checks.impl.DepthComplexityCheck
import com.redcell.gqlanalyzer.checks.impl.DirectiveOverloadCheck
import com.redcell.gqlanalyzer.checks.impl.EngineFingerprintCheck
import com.redcell.gqlanalyzer.checks.impl.FieldAuthzCheck
import com.redcell.gqlanalyzer.checks.impl.FieldDuplicationCheck
import com.redcell.gqlanalyzer.checks.impl.FieldSuggestionCheck
import com.redcell.gqlanalyzer.checks.impl.GraphiqlExposedCheck
import com.redcell.gqlanalyzer.checks.impl.IdorEnumerationCheck
import com.redcell.gqlanalyzer.checks.impl.InjectionSeederCheck
import com.redcell.gqlanalyzer.checks.impl.IntrospectionCheck
import com.redcell.gqlanalyzer.checks.impl.MassAssignmentCheck
import com.redcell.gqlanalyzer.checks.impl.OobCanaryInjectionCheck
import com.redcell.gqlanalyzer.checks.impl.SensitiveFlowCheck
import com.redcell.gqlanalyzer.checks.impl.UserEnumerationCheck
import com.redcell.gqlanalyzer.checks.impl.PaginationAbuseCheck
import com.redcell.gqlanalyzer.checks.impl.SsrfSeederCheck
import com.redcell.gqlanalyzer.checks.impl.TracingExtensionsCheck
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
        // v0.4.0 — recon & fingerprinting
        EngineFingerprintCheck(),
        AltIntrospectionCheck(),
        ApqDetectionCheck(),
        TracingExtensionsCheck(),
        DeferStreamCheck(),
        DeprecatedFieldInventoryCheck(),
        // v0.5.0 — DoS completeness
        CircularFragmentCheck(),
        PaginationAbuseCheck(),
        FieldDuplicationCheck(),
        // v0.6.0 — active out-of-band confirmation (Burp Collaborator)
        ActiveSsrfCheck(),
        OobCanaryInjectionCheck(),
        // v0.13.0 — active in-band injection (error-based + SSTI reflection)
        ActiveInjectionCheck(),
        // v0.7.0 — auth & deeper authz
        IdorEnumerationCheck(),
        AuthAmplificationCheck(),
        CorsCheck(),
        // v0.8.0 — API2/API6 breadth + CSWSH
        SensitiveFlowCheck(),
        UserEnumerationCheck(),
        CswshCheck(),
    )
}
