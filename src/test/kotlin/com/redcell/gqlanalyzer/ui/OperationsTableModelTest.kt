package com.redcell.gqlanalyzer.ui

import com.redcell.gqlanalyzer.checks.SchemaFixtures
import com.redcell.gqlanalyzer.engine.OperationEnumerator
import com.redcell.gqlanalyzer.model.OperationStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class OperationsTableModelTest {

    private val ops = OperationEnumerator.enumerate(SchemaFixtures.full())

    @Test
    fun `queries preselected and mutations not`() {
        val model = OperationsTableModel()
        model.setOperations(ops)
        val selected = model.selectedOperations().map { it.name }.toSet()
        assertTrue("QUERY.user" in selected)
        assertTrue("QUERY.me" in selected)
        assertTrue("MUTATION.updateUser" !in selected) // mutation off by default
    }

    @Test
    fun `checkbox column is editable and toggles selection`() {
        val model = OperationsTableModel()
        model.setOperations(ops)
        assertEquals(java.lang.Boolean::class.java, model.getColumnClass(0))
        assertTrue(model.isCellEditable(0, 0))
        assertTrue(!model.isCellEditable(0, 1))

        // Turn the mutation on.
        val mutRow = (0 until model.rowCount).first { model.getValueAt(it, 2) == "updateUser" }
        model.setValueAt(true, mutRow, 0)
        assertTrue(model.selectedOperations().any { it.name == "MUTATION.updateUser" })
    }

    @Test
    fun `applyStatuses updates status and finding counts`() {
        val model = OperationsTableModel()
        model.setOperations(ops)
        val me = ops.first { it.name == "QUERY.me" }
        model.applyStatuses(mapOf(me to OperationStatus.RESOLVED), mapOf(me to 2))
        val row = (0 until model.rowCount).first { model.getValueAt(it, 2) == "me" }
        assertEquals("RESOLVED", model.getValueAt(row, 5))
        assertEquals("2", model.getValueAt(row, 6))
    }
}
