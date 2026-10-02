package com.redcell.gqlanalyzer.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import com.redcell.gqlanalyzer.engine.AnalyzerService
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.schema.SchemaModel
import com.redcell.gqlanalyzer.scanner.FindingAuditIssue
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
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
 * Per-request detail panel: config, schema tree, a selectable operations grid, and
 * a findings grid, with Enumerate (introspect + endpoint checks + list operations)
 * and Scan selected (actively test the ticked operations) actions.
 */
class TargetPanel(
    private val api: MontoyaApi,
    private val base: HttpRequest,
    private val service: AnalyzerService,
) {
    @Volatile private var schema: SchemaModel? = null
    private val findings = mutableListOf<Finding>()

    private val statusLabel = JLabel(" ")
    private val enumerateButton = JButton("Enumerate")
    private val scanButton = JButton("Scan selected").apply { isEnabled = false }

    private val identityA = JTextArea(3, 24)
    private val identityB = JTextArea(3, 24)
    private val knownIdField = JTextField(16)

    private val operationsModel = OperationsTableModel()
    private val operationsTable = JTable(operationsModel)
    private val findingsModel = FindingsTableModel()
    private val findingsTable = JTable(findingsModel)
    private val schemaTree = JTree(SchemaTree.build(null))

    val component: Component = buildUi()

    private fun buildUi(): Component {
        val root = JPanel(BorderLayout(8, 8))
        root.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        root.add(buildTop(), BorderLayout.NORTH)
        root.add(buildCenter(), BorderLayout.CENTER)
        enumerateButton.addActionListener { enumerate() }
        scanButton.addActionListener { scanSelected() }
        return root
    }

    private fun buildTop(): Component {
        val top = JPanel(BorderLayout(8, 8))

        val buttons = JPanel(FlowLayout(FlowLayout.LEFT, 8, 0))
        buttons.add(enumerateButton)
        buttons.add(scanButton)

        val header = JPanel(BorderLayout(8, 8))
        header.add(JLabel(targetLabel()), BorderLayout.CENTER)
        header.add(buttons, BorderLayout.EAST)

        val config = JPanel(GridLayout(1, 3, 8, 8))
        config.border = BorderFactory.createTitledBorder("Config (optional) — one 'Header: value' per line")
        config.add(labeled("Identity A (low-priv)", JScrollPane(identityA)))
        config.add(labeled("Identity B (attacker)", JScrollPane(identityB)))
        config.add(labeled("Known object id (A-owned)", knownIdField))

        top.add(header, BorderLayout.NORTH)
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
        val treeScroll = JScrollPane(schemaTree).apply { preferredSize = Dimension(320, 400) }

        val opsScroll = JScrollPane(operationsTable)
        opsScroll.border = BorderFactory.createTitledBorder("Operations — tick to test (queries preselected; mutations/subscriptions off)")
        val findingsScroll = JScrollPane(findingsTable)
        findingsScroll.border = BorderFactory.createTitledBorder("Findings")
        val rightSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, opsScroll, findingsScroll)
        rightSplit.resizeWeight = 0.5
        rightSplit.dividerLocation = 240

        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, treeScroll, rightSplit)
        split.dividerLocation = 330
        split.resizeWeight = 0.3
        return split
    }

    private fun targetLabel(): String = runCatching { base.url() }.getOrDefault(base.path())

    private fun readConfig(): CheckConfig = CheckConfig(
        authHeadersA = AnalyzerTab.parseHeaders(identityA.text),
        authHeadersB = AnalyzerTab.parseHeaders(identityB.text),
        knownObjectId = knownIdField.text.trim().ifEmpty { null },
    )

    /** Introspect, enumerate operations, and run endpoint-level checks. */
    fun enumerate() {
        val config = readConfig()
        enumerateButton.isEnabled = false
        statusLabel.text = "Enumerating…"
        runOffEdt("gql-enumerate") {
            val res = runCatching { service.enumerate(base, config) }
            SwingUtilities.invokeLater {
                enumerateButton.isEnabled = true
                res.onFailure { statusLabel.text = "Error: ${it.message}" }
                    .onSuccess { r ->
                        schema = r.schema
                        schemaTree.model = SchemaTree.build(r.schema)
                        operationsModel.setOperations(r.operations)
                        findings.clear()
                        findings.addAll(r.endpointFindings)
                        findingsModel.setFindings(findings.toList())
                        r.endpointFindings.forEach { api.siteMap().add(FindingAuditIssue.toAuditIssue(it)) }
                        scanButton.isEnabled = r.operations.isNotEmpty()
                        val intro = if (r.introspectionEnabled) "introspection ON" else "introspection off/partial"
                        statusLabel.text = "${r.operations.size} operation(s); ${r.endpointFindings.size} endpoint finding(s); $intro."
                    }
            }
        }
    }

    /** Actively test the ticked operations. */
    fun scanSelected() {
        val selected = operationsModel.selectedOperations()
        if (selected.isEmpty()) {
            statusLabel.text = "Tick at least one operation to scan."
            return
        }
        val config = readConfig()
        val snapshotSchema = schema
        scanButton.isEnabled = false
        enumerateButton.isEnabled = false
        statusLabel.text = "Scanning ${selected.size} operation(s)…"
        runOffEdt("gql-op-scan") {
            val res = runCatching { service.scanOperations(base, config, snapshotSchema, selected) }
            SwingUtilities.invokeLater {
                scanButton.isEnabled = true
                enumerateButton.isEnabled = true
                res.onFailure { statusLabel.text = "Error: ${it.message}" }
                    .onSuccess { r ->
                        findings.addAll(r.findings)
                        findingsModel.setFindings(findings.toList())
                        r.findings.forEach { api.siteMap().add(FindingAuditIssue.toAuditIssue(it)) }
                        val perOp = countPerOperation(selected, r.findings)
                        operationsModel.applyStatuses(r.statuses, perOp)
                        statusLabel.text = "Scanned ${selected.size}; ${r.findings.size} new finding(s). Issues added to site map."
                        api.logging().logToOutput("GraphQL Analyzer: scanned ${selected.size} operation(s), ${r.findings.size} finding(s).")
                    }
            }
        }
    }

    private fun countPerOperation(ops: List<Operation>, found: List<Finding>): Map<Operation, Int> =
        ops.associateWith { op -> found.count { it.location.endsWith("#${op.name}") || it.location == op.name } }

    private fun runOffEdt(name: String, block: () -> Unit) {
        Thread(block, name).apply { isDaemon = true }.start()
    }
}
