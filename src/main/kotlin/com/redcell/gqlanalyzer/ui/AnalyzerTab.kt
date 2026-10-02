package com.redcell.gqlanalyzer.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.engine.AnalyzerService
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.util.concurrent.atomic.AtomicInteger
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTabbedPane
import javax.swing.JTextArea
import javax.swing.SwingUtilities

/**
 * The "GraphQL OWASP-API Analyzer" suite tab: a Repeater-style container. Each
 * request sent to the extension becomes its own closable inner tab (a [TargetPanel]),
 * so multiple targets are retained instead of the last one overwriting the rest.
 */
class AnalyzerTab(
    private val api: MontoyaApi,
    private val service: AnalyzerService = AnalyzerService(api),
) {
    private val tabs = JTabbedPane()
    private val counter = AtomicInteger(0)
    private val targets = java.util.Collections.synchronizedList(mutableListOf<Component>())

    val component: Component = buildUi()

    private fun buildUi(): Component {
        val root = JPanel(BorderLayout())
        root.add(tabs, BorderLayout.CENTER)
        addWelcomeTab()
        return root
    }

    private fun addWelcomeTab() {
        val panel = JPanel(BorderLayout())
        panel.border = BorderFactory.createEmptyBorder(16, 16, 16, 16)
        // Plain-text area (no HTML) so no markup can render literally under Burp's L&F.
        val welcome = JTextArea(WELCOME_TEXT).apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            isOpaque = false
            border = null
        }
        panel.add(welcome, BorderLayout.NORTH)
        tabs.addTab("Welcome", panel)
    }

    /**
     * Open (and focus) a new target tab for the given request. Safe to call from
     * any thread. Returns nothing; the tab is retained until the user closes it.
     */
    fun addTarget(request: HttpRequest) {
        val n = counter.incrementAndGet()
        val panel = TargetPanel(api, request, service)
        val content = panel.component
        val title = "#$n ${hostOf(request)}"
        targets.add(content)
        runOnEdt {
            tabs.addTab(title, content)
            val index = tabs.indexOfComponent(content)
            tabs.setTabComponentAt(index, closableHeader(title, content))
            tabs.selectedComponent = content
        }
    }

    /** Count of open target tabs (excludes the Welcome tab). */
    fun targetCount(): Int = targets.size

    private fun runOnEdt(block: () -> Unit) {
        if (SwingUtilities.isEventDispatchThread()) block() else SwingUtilities.invokeLater(block)
    }

    private fun hostOf(request: HttpRequest): String =
        runCatching { request.httpService().host() }.getOrNull()
            ?: runCatching { request.url() }.getOrNull()
            ?: request.path()

    private fun closableHeader(title: String, content: Component): Component {
        val header = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        header.isOpaque = false
        header.add(JLabel(title))
        val close = JButton("×").apply {
            isBorderPainted = false
            isContentAreaFilled = false
            isFocusable = false
            margin = java.awt.Insets(0, 4, 0, 0)
            toolTipText = "Close"
            addActionListener {
                targets.remove(content)
                tabs.remove(content)
            }
        }
        header.add(close)
        return header
    }

    companion object {
        const val WELCOME_TEXT =
            "No targets yet. Right-click a request → \"Send to GraphQL Analyzer\" to open a " +
                "target tab, then use Enumerate and Scan selected."

        /** "Header: value" lines -> map; blanks and malformed lines ignored. */
        fun parseHeaders(text: String): Map<String, String> =
            text.lineSequence()
                .mapNotNull { line ->
                    val idx = line.indexOf(':')
                    if (idx <= 0) return@mapNotNull null
                    val name = line.substring(0, idx).trim()
                    val value = line.substring(idx + 1).trim()
                    if (name.isEmpty() || value.isEmpty()) null else name to value
                }
                .toMap()
    }
}
