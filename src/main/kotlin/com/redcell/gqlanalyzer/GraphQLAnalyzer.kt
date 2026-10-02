package com.redcell.gqlanalyzer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi

/**
 * Entry point for the GraphQL OWASP-API Analyzer Burp extension.
 *
 * Phase 0: registers the extension name and logs startup. Detection hooks,
 * schema tooling, checks, scanner integration, and the UI tab are wired in
 * subsequent phases.
 */
class GraphQLAnalyzer : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(EXTENSION_NAME)
        api.logging().logToOutput("$EXTENSION_NAME v$VERSION loaded.")
    }

    companion object {
        const val EXTENSION_NAME = "GraphQL OWASP-API Analyzer"
        const val VERSION = "0.1.0"
    }
}
