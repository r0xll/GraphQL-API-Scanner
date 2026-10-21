package com.redcell.gqlanalyzer

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import com.redcell.gqlanalyzer.detection.BurpEdition
import com.redcell.gqlanalyzer.detection.EndpointTagger
import burp.api.montoya.scanner.scancheck.ScanCheckType
import com.redcell.gqlanalyzer.engine.Workers
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

        // Owns all background threads so they terminate on unload (BApp rule 4).
        val workers = Workers()
        api.extension().registerUnloadingHandler { workers.shutdown() }

        // Passive GraphQL fingerprinting on all proxied traffic.
        api.http().registerHttpHandler(EndpointTagger(api))

        // Analyzer UI + right-click driver.
        val tab = AnalyzerTab(api, workers)
        api.userInterface().registerSuiteTab(EXTENSION_NAME, tab.component)
        api.userInterface().registerContextMenuItemsProvider(GraphQLContextMenu(api, tab))

        // Passive scan issue for detected endpoints — Burp Scanner is Professional-only, so
        // register it only on Pro/DAST. On Community the active (HTTP-driven) scanner, the tab,
        // and the proxy-traffic highlighting still work; the formal passive issue is skipped.
        // The call is wrapped defensively in case edition detection is wrong on some build.
        val professional = runCatching { BurpEdition.isProfessional(api.burpSuite().version().name()) }.getOrDefault(true)
        if (professional) {
            runCatching { api.scanner().registerPassiveScanCheck(GraphQLScanCheck(), ScanCheckType.PER_REQUEST) }
                .onFailure { api.logging().logToError("Passive scan check not registered: ${it.message}") }
        } else {
            api.logging().logToOutput(
                "$EXTENSION_NAME: Community edition detected — Burp Scanner/Collaborator features are off " +
                    "(passive issue + site-map issues disabled). Enumerate and Scan selected work; findings show in the tab.",
            )
        }

        val mode = if (professional) "Professional" else "Community"
        api.logging().logToOutput("$EXTENSION_NAME v$VERSION loaded ($mode). Passive detection + UI tab active.")
    }

    companion object {
        const val EXTENSION_NAME = "GraphQL OWASP-API Analyzer"
        const val VERSION = "0.16.2"
    }
}
