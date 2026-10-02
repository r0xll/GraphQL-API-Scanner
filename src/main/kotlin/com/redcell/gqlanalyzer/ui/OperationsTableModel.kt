package com.redcell.gqlanalyzer.ui

import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.model.OperationKind
import com.redcell.gqlanalyzer.model.OperationStatus
import com.redcell.gqlanalyzer.schema.GqlInputValue
import javax.swing.table.AbstractTableModel

/**
 * Backing model for the operations grid. Column 0 is an editable checkbox; the
 * operator ticks which operations to actively test. Queries default selected;
 * mutations and subscriptions default unselected (write-safety by selection).
 */
class OperationsTableModel : AbstractTableModel() {

    data class Row(
        val operation: Operation,
        var selected: Boolean,
        var status: OperationStatus = OperationStatus.NOT_RUN,
        var findings: Int = 0,
    )

    private val columns = arrayOf("Test", "Kind", "Operation", "Args", "Returns", "Status", "Findings")
    private val rows = mutableListOf<Row>()

    fun setOperations(operations: List<Operation>) {
        rows.clear()
        operations.forEach { op ->
            rows += Row(op, selected = op.kind == OperationKind.QUERY)
        }
        fireTableDataChanged()
    }

    fun selectedOperations(): List<Operation> = rows.filter { it.selected }.map { it.operation }

    fun rowFor(operation: Operation): Row? = rows.firstOrNull { it.operation == operation }

    /** Apply scan results: set each operation's status and increment its finding count. */
    fun applyStatuses(statuses: Map<Operation, OperationStatus>, findingsPerOp: Map<Operation, Int>) {
        rows.forEach { row ->
            statuses[row.operation]?.let { row.status = it }
            findingsPerOp[row.operation]?.let { row.findings = it }
        }
        fireTableDataChanged()
    }

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]

    override fun getColumnClass(columnIndex: Int): Class<*> =
        if (columnIndex == 0) java.lang.Boolean::class.java else String::class.java

    override fun isCellEditable(rowIndex: Int, columnIndex: Int): Boolean = columnIndex == 0

    override fun setValueAt(aValue: Any?, rowIndex: Int, columnIndex: Int) {
        if (columnIndex == 0 && aValue is Boolean) {
            rows[rowIndex].selected = aValue
            fireTableCellUpdated(rowIndex, columnIndex)
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val row = rows[rowIndex]
        val op = row.operation
        return when (columnIndex) {
            0 -> row.selected
            1 -> op.kind.name
            2 -> op.field.name
            3 -> op.field.args.joinToString(", ") { argLabel(it) }
            4 -> op.field.typeRef.namedType() ?: ""
            5 -> row.status.name
            6 -> if (row.findings > 0) row.findings.toString() else ""
            else -> ""
        }
    }

    private fun argLabel(arg: GqlInputValue): String =
        "${arg.name}: ${arg.typeRef.namedType()}${if (arg.typeRef.isNonNull()) "!" else ""}"
}
