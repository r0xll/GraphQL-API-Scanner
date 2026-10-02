package com.redcell.gqlanalyzer.ui

import com.redcell.gqlanalyzer.checks.SchemaFixtures
import javax.swing.tree.DefaultMutableTreeNode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AnalyzerTabTest {

    @Test
    fun `parseHeaders reads header lines and ignores junk`() {
        val text = """
            Authorization: Bearer abc123
            X-Tenant:  t-1
            malformed line
            : novalue
            Empty:
        """.trimIndent()
        val headers = AnalyzerTab.parseHeaders(text)
        assertEquals(mapOf("Authorization" to "Bearer abc123", "X-Tenant" to "t-1"), headers)
    }

    @Test
    fun `schema tree is a placeholder when no schema`() {
        val model = SchemaTree.build(null)
        val root = model.root as DefaultMutableTreeNode
        assertTrue(root.userObject.toString().contains("No schema"))
    }

    @Test
    fun `schema tree lists roots first with fields and args`() {
        val model = SchemaTree.build(SchemaFixtures.full())
        val root = model.root as DefaultMutableTreeNode
        val typeLabels = (0 until root.childCount).map { (root.getChildAt(it) as DefaultMutableTreeNode).userObject.toString() }
        assertTrue(typeLabels.first().startsWith("Query"))
        assertTrue(typeLabels.any { it.startsWith("Mutation") })
        // Query node should contain the user(id: ID!) field signature.
        val queryNode = root.getChildAt(0) as DefaultMutableTreeNode
        val fieldLabels = (0 until queryNode.childCount).map { (queryNode.getChildAt(it) as DefaultMutableTreeNode).userObject.toString() }
        assertTrue(fieldLabels.any { it.contains("user(") && it.contains("id: ID!") })
    }
}
