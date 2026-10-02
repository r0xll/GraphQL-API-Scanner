package com.redcell.gqlanalyzer.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.engine.AnalyzerService
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.scanner.FindingAuditIssue
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.GridLayout
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.JTree
import javax.swing.SwingUtilities

/**
 * The "GraphQL Analyzer" suite tab: schema tree + findings grid + a run button,
 * plus operator config (two identities for BOLA/BFLA, a known object id).
 * Checks run on a background thread; results publish to the grid, the schema
 * tree, and Burp's site map (as AuditIssues).
 */
class AnalyzerTab(
    private val api: MontoyaApi,
    private val service: AnalyzerService = AnalyzerService(api),
) {
    @Volatile
    private var baseRequest: HttpRequest? = null

    private val endpointLabel = JLabel("No target selected — right-click a request > \"Send to GraphQL Analyzer\".")
    private val statusLabel = JLabel(" ")
    private val runButton = JButton("Run OWASP checks")

    private val identityA = JTextArea(3, 30)
    private val identityB = JTextArea(3, 30)
    private val knownIdField = JTextField(20)

    private val findingsModel = FindingsTableModel()
    private val findingsTable = JTable(findingsModel)
    private val schemaTree = JTree(SchemaTree.build(null))

    /** Root component registered as the suite tab. */
    val component: Component = buildUi()

    private fun buildUi(): Component {
        val root = JPanel(BorderLayout(8, 8))
        root.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        root.add(buildTop(), BorderLayout.NORTH)
        root.add(buildCenter(), BorderLayout.CENTER)
        runButton.addActionListener { runChecks() }
        return root
    }

    private fun buildTop(): Component {
        val top = JPanel(BorderLayout(8, 8))

        val controls = JPanel(BorderLayout(8, 8))
        controls.add(endpointLabel, BorderLayout.CENTER)
        controls.add(runButton, BorderLayout.EAST)

        val config = JPanel(GridLayout(1, 3, 8, 8))
        config.border = BorderFactory.createTitledBorder("Config (optional) — one 'Header: value' per line")
        config.add(labeled("Identity A (low-priv)", JScrollPane(identityA)))
        config.add(labeled("Identity B (attacker)", JScrollPane(identityB)))
        config.add(labeled("Known object id (A-owned)", knownIdField))

        top.add(controls, BorderLayout.NORTH)
        top.add(config, BorderLayout.CENTER)
        top.add(statusLabel, BorderLayout.SOUTH)
        return top
    }

    private fun labeled(title: String, inner: Component): JPanel {
        val p = JPanel(BorderLayout(4, 4))
        p.add(JLabel(title), BorderLayout.NORTH)
        p.add(inner, BorderLayout.CENTER)
        return p
    }

    private fun buildCenter(): Component {
        val treeScroll = JScrollPane(schemaTree).apply { preferredSize = Dimension(360, 400) }
        val tableScroll = JScrollPane(findingsTable)
        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, tableScroll)
        split.dividerLocation = 380
        split.resizeWeight = 0.35
        return split
    }

    fun setBaseRequest(request: HttpRequest) {
        baseRequest = request
        val url = runCatching { request.url() }.getOrDefault(request.path())
        SwingUtilities.invokeLater { endpointLabel.text = "Target: $url" }
    }

    /** Parse config fields into a [CheckConfig]. */
    private fun readConfig(): CheckConfig = CheckConfig(
        authHeadersA = parseHeaders(identityA.text),
        authHeadersB = parseHeaders(identityB.text),
        knownObjectId = knownIdField.text.trim().ifEmpty { null },
    )

    fun runChecks() {
        val base = baseRequest
        if (base == null) {
            statusLabel.text = "Select a target request first."
            return
        }
        val config = readConfig()
        runButton.isEnabled = false
        statusLabel.text = "Running checks…"
        Thread({
            val result = runCatching { service.analyze(base, config) }
            SwingUtilities.invokeLater {
                runButton.isEnabled = true
                result.onFailure { statusLabel.text = "Error: ${it.message}" }
                    .onSuccess { res ->
                        schemaTree.model = SchemaTree.build(res.schema)
                        findingsModel.setFindings(res.findings)
                        res.findings.forEach { api.siteMap().add(FindingAuditIssue.toAuditIssue(it)) }
                        val introState = if (res.introspectionEnabled) "introspection ON" else "introspection off/partial"
                        statusLabel.text = "${res.findings.size} finding(s); $introState. Issues added to site map."
                        api.logging().logToOutput("GraphQL Analyzer: ${res.findings.size} finding(s) on target.")
                    }
            }
        }, "gql-analyzer-run").apply { isDaemon = true }.start()
    }

    companion object {
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
