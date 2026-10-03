package com.redcell.gqlanalyzer.ui

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import com.redcell.gqlanalyzer.engine.AnalyzerService
import com.redcell.gqlanalyzer.model.CheckConfig
import com.redcell.gqlanalyzer.model.Finding
import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.model.OperationStatus
import com.redcell.gqlanalyzer.schema.SchemaModel
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JDialog
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JSplitPane
import javax.swing.SwingUtilities

/**
 * A Repeater-style editor for a single GraphQL operation: shows the exact request the
 * scanner sent (editable) and the API's response, lets the operator edit the request —
 * query, variables, or headers — re-send it, and apply the re-scored status/findings
 * back to the operations grid. Built on Burp's native editors so it behaves like Repeater.
 *
 * The request is sent only when the operator clicks Send (the Repeater-equivalent gate);
 * a mutation goes out only because the operator opened this editor and clicked Send.
 *
 * This is Montoya-runtime UI (not unit-tested), consistent with scanner/FindingAuditIssue.
 */
class OperationEditorDialog(
    private val api: MontoyaApi,
    private val service: AnalyzerService,
    private val op: Operation,
    private val schema: SchemaModel?,
    private val config: CheckConfig,
    seedRequest: HttpRequest,
    seedResponse: HttpResponse?,
    private val onApply: (OperationStatus, List<Finding>) -> Unit,
) {
    private val requestEditor = api.userInterface().createHttpRequestEditor()
    private val responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)

    private val statusLabel = JLabel(" ")
    private val sendButton = JButton("Send")
    private val applyButton = JButton("Apply to grid").apply { isEnabled = false }
    private val closeButton = JButton("Close")

    @Volatile private var latestStatus: OperationStatus? = null
    @Volatile private var latestFindings: List<Finding> = emptyList()

    init {
        requestEditor.setRequest(seedRequest)
        seedResponse?.let { responseEditor.setResponse(it) }
    }

    /** Build and show the modal dialog, owned by [parent]'s window. */
    fun show(parent: Component) {
        val owner = SwingUtilities.getWindowAncestor(parent)
        val dialog = JDialog(owner, "Edit & re-test: ${op.parentTypeName}.${op.field.name}", java.awt.Dialog.ModalityType.MODELESS)
        dialog.contentPane = buildContent()
        dialog.minimumSize = Dimension(720, 520)
        dialog.pack()
        dialog.setLocationRelativeTo(owner)

        sendButton.addActionListener { send() }
        applyButton.addActionListener {
            latestStatus?.let { onApply(it, latestFindings) }
            dialog.dispose()
        }
        closeButton.addActionListener { dialog.dispose() }

        dialog.isVisible = true
    }

    private fun buildContent(): JPanel {
        val root = JPanel(BorderLayout(8, 8))
        root.border = BorderFactory.createEmptyBorder(8, 8, 8, 8)

        val reqPanel = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Request (editable — edit query/variables/headers, then Send)")
            add(requestEditor.uiComponent(), BorderLayout.CENTER)
        }
        val rspPanel = JPanel(BorderLayout()).apply {
            border = BorderFactory.createTitledBorder("Response (API error / result)")
            add(responseEditor.uiComponent(), BorderLayout.CENTER)
        }
        val split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, reqPanel, rspPanel).apply {
            resizeWeight = 0.5
            dividerLocation = 360
        }

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, 8, 0)).apply {
            add(sendButton)
            add(applyButton)
            add(closeButton)
        }
        val south = JPanel(BorderLayout(8, 8)).apply {
            add(statusLabel, BorderLayout.CENTER)
            add(buttons, BorderLayout.EAST)
        }

        root.add(split, BorderLayout.CENTER)
        root.add(south, BorderLayout.SOUTH)
        return root
    }

    private fun send() {
        val edited = requestEditor.request
        sendButton.isEnabled = false
        statusLabel.text = "Sending…"
        Thread({
            val res = runCatching { service.rerunOperation(edited, config, schema, op) }
            SwingUtilities.invokeLater {
                sendButton.isEnabled = true
                res.onFailure { statusLabel.text = "Error: ${it.message}" }
                    .onSuccess { r ->
                        r.requestResponse.response()?.let { responseEditor.setResponse(it) }
                        latestStatus = r.status
                        latestFindings = r.findings
                        applyButton.isEnabled = true
                        statusLabel.text = "Status: ${r.status.name} — ${r.findings.size} finding(s). Apply to push to the grid."
                    }
            }
        }, "gql-op-retest").apply { isDaemon = true }.start()
    }
}
