package com.redcell.gqlanalyzer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.redcell.gqlanalyzer.detection.EndpointTagger
import burp.api.montoya.scanner.scancheck.ScanCheckType
import com.redcell.gqlanalyzer.scanner.GraphQLScanCheck
import com.redcell.gqlanalyzer.ui.AnalyzerTab
import com.redcell.gqlanalyzer.ui.GraphQLContextMenu

/**
 * Entry point for the GraphQL OWASP-API Analyzer Burp extension.
 *
 * Wires passive detection, the analyzer UI tab, the right-click action, and the
 * scan check. Active OWASP checks are operator-driven (tab / context menu) to
 * keep scanning proof-level and non-surprising.
 */
class GraphQLAnalyzer : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName(EXTENSION_NAME)

        // Passive GraphQL fingerprinting on all proxied traffic.
        api.http().registerHttpHandler(EndpointTagger(api))

        // Analyzer UI + right-click driver.
        val tab = AnalyzerTab(api)
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab.component)
        api.userInterface().registerContextMenuItemsProvider(GraphQLContextMenu(api, tab))

        // Passive scan issue for detected endpoints.
        api.scanner().registerPassiveScanCheck(GraphQLScanCheck(), ScanCheckType.PER_REQUEST)

        api.logging().logToOutput("$EXTENSION_NAME v$VERSION loaded. Passive detection, UI tab, and scan check active.")
    }

    companion object {
        const val EXTENSION_NAME = "GraphQL OWASP-API Analyzer"
        const val VERSION = "0.7.0"
    }
}
