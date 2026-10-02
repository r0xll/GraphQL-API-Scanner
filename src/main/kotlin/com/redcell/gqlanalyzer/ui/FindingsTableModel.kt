package com.redcell.gqlanalyzer.ui

import com.redcell.gqlanalyzer.model.Finding
import javax.swing.table.AbstractTableModel

/** Backing model for the findings grid. */
class FindingsTableModel : AbstractTableModel() {

    private val columns = arrayOf("Severity", "Confidence", "OWASP", "Check", "Finding", "Location")
    private val rows = mutableListOf<Finding>()

    fun setFindings(findings: List<Finding>) {
        rows.clear()
        rows.addAll(findings)
        fireTableDataChanged()
    }

    fun findingAt(row: Int): Finding? = rows.getOrNull(row)

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val f = rows[rowIndex]
        return when (columnIndex) {
            0 -> f.severity.name
            1 -> f.confidence.name
            2 -> f.owaspId
            3 -> f.checkId
            4 -> f.name
            5 -> f.location
            else -> ""
        }
    }
}
