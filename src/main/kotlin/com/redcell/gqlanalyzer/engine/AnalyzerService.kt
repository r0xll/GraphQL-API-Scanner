package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.checks.AllChecks
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.CheckContext
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.schema.IntrospectionRunner
import com.redcell.gqlanalyzer.schema.SchemaModel

/**
 * Ties introspection + the check engine together for a single endpoint. UI and
 * context-menu both drive this; it performs network I/O so callers must run it
 * off the Swing EDT.
 */
class AnalyzerService(
    private val api: MontoyaApi,
    private val engine: CheckEngine = CheckEngine(AllChecks.list()),
    private val introspection: IntrospectionRunner = IntrospectionRunner(api),
) {
    data class Result(
        val schema: SchemaModel?,
        val introspectionEnabled: Boolean,
        val findings: List<Finding>,
    )

    fun analyze(base: HttpRequest, config: CheckConfig = CheckConfig()): Result {
        val intro = introspection.run(base)
        val ctx = CheckContext(api, base, intro.schema, config)
        val findings = engine.run(ctx)
        return Result(intro.schema, intro.introspectionEnabled, findings)
    }
}
