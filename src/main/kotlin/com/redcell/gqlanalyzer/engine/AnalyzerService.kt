package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.checks.AllChecks
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.schema.IntrospectionRunner
import com.redcell.gqlanalyzer.schema.SchemaModel

/**
 * Ties introspection + the check engine + the operation scanner together for a
 * single endpoint. UI and context-menu drive this; it performs network I/O so
 * callers must run it off the Swing EDT.
 */
class AnalyzerService(
    private val api: MontoyaApi,
    private val engine: CheckEngine = CheckEngine(AllChecks.list()),
    private val introspection: IntrospectionRunner = IntrospectionRunner(api),
    private val operationScanner: OperationScanner = OperationScanner(),
) {
    data class Result(
        val schema: SchemaModel?,
        val introspectionEnabled: Boolean,
        val findings: List<Finding>,
    )

    /** Endpoint-level quick checks (introspection/CSRF/batching/depth/...). */
    fun analyze(base: HttpRequest, config: CheckConfig = CheckConfig()): Result {
        val intro = introspection.run(base)
        val ctx = CheckContext(api, base, intro.schema, config)
        val findings = engine.run(ctx)
        return Result(intro.schema, intro.introspectionEnabled, findings)
    }

    data class EnumerationResult(
        val schema: SchemaModel?,
        val introspectionEnabled: Boolean,
        val operations: List<Operation>,
        val endpointFindings: List<Finding>,
    )

    /** Confirm introspection, enumerate operations, and run endpoint-level checks once. */
    fun enumerate(base: HttpRequest, config: CheckConfig = CheckConfig()): EnumerationResult {
        val intro = introspection.run(base)
        return build(base, config, intro.schema, intro.introspectionEnabled)
    }

    /**
     * Enumerate against an operator-supplied (out-of-band) schema: no introspection
     * request for the schema itself, but endpoint-level checks still probe the live target.
     */
    fun enumerateWithProvidedSchema(
        base: HttpRequest,
        config: CheckConfig,
        schema: SchemaModel,
    ): EnumerationResult = build(base, config, schema, introspectionEnabled = false)

    private fun build(
        base: HttpRequest,
        config: CheckConfig,
        schema: SchemaModel?,
        introspectionEnabled: Boolean,
    ): EnumerationResult {
        val ctx = CheckContext(api, base, schema, config)
        val endpointFindings = engine.run(ctx)
        val operations = schema?.let { OperationEnumerator.enumerate(it) } ?: emptyList()
        return EnumerationResult(schema, introspectionEnabled, operations, endpointFindings)
    }

    /** Actively test the operations the operator selected. */
    fun scanOperations(
        base: HttpRequest,
        config: CheckConfig,
        schema: SchemaModel?,
        operations: List<Operation>,
    ): OperationScanner.ScanResult {
        val ctx = CheckContext(api, base, schema, config)
        return operationScanner.scan(ctx, operations)
    }
}
