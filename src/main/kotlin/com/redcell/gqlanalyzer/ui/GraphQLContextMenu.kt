package com.redcell.gqlanalyzer.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenuItem

/**
 * Right-click action to send the selected request to the GraphQL Analyzer as a new
 * target tab. Each invocation opens its own tab, so multiple requests are retained.
 */
class GraphQLContextMenu(
    private val api: MontoyaApi,
    private val tab: AnalyzerTab,
) : ContextMenuItemsProvider {

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val target = selectedRequestResponse(event) ?: return emptyList()
        val request = target.request() ?: return emptyList()

        val sendItem = JMenuItem("Send to GraphQL Analyzer").apply {
            addActionListener { tab.addTarget(request) }
        }
        return listOf(sendItem)
    }

    private fun selectedRequestResponse(event: ContextMenuEvent): HttpRequestResponse? {
        val fromEditor = event.messageEditorRequestResponse()
        if (fromEditor.isPresent) return fromEditor.get().requestResponse()
        return event.selectedRequestResponses().firstOrNull()
    }
}
