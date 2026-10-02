package com.redcell.gqlanalyzer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.redcell.gqlanalyzer.detection.EndpointTagger

/**
 * Entry point for the GraphQL OWASP-API Analyzer Burp extension.
 *
 * Wires the passive detection hook; schema tooling, checks, scanner
 * integration, and the UI tab are added in later phases.
 */
class GraphQLAnalyzer : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(EXTENSION_NAME)
        api.http().registerHttpHandler(EndpointTagger(api))
        api.logging().logToOutput("$EXTENSION_NAME v$VERSION loaded. Passive GraphQL detection active.")
    }

    companion object {
        const val EXTENSION_NAME = "GraphQL OWASP-API Analyzer"
        const val VERSION = "0.1.0"
    }
}
