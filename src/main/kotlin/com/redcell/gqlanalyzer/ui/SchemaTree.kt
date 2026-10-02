package com.redcell.gqlanalyzer.ui

import com.redcell.gqlanalyzer.schema.GqlField
import com.redcell.gqlanalyzer.schema.SchemaModel
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import javax.swing.tree.TreeModel

/** Builds a JTree model from a [SchemaModel]. */
object SchemaTree {

    fun build(schema: SchemaModel?): TreeModel {
        if (schema == null) {
            return DefaultTreeModel(DefaultMutableTreeNode("No schema — run checks to introspect"))
        }
        val label = if (schema.reconstructed) "Schema (reconstructed)" else "Schema"
        val root = DefaultMutableTreeNode(label)

        // Roots first, then the rest, each type with its fields and args.
        val rootNames = listOfNotNull(schema.queryTypeName, schema.mutationTypeName, schema.subscriptionTypeName)
        val ordered = rootNames.mapNotNull { schema.typesByName[it] } +
            schema.types.filter { it.name !in rootNames && !it.name.startsWith("__") }

        for (type in ordered) {
            val typeNode = DefaultMutableTreeNode("${type.name} : ${type.kind}")
            type.fields.forEach { typeNode.add(fieldNode(it)) }
            type.inputFields.forEach { typeNode.add(DefaultMutableTreeNode("${it.name}: ${it.typeRef.namedType()}")) }
            if (type.enumValues.isNotEmpty()) {
                typeNode.add(DefaultMutableTreeNode("enum values: ${type.enumValues.joinToString(", ")}"))
            }
            root.add(typeNode)
        }
        return DefaultTreeModel(root)
    }

    private fun fieldNode(field: GqlField): DefaultMutableTreeNode {
        val sig = buildString {
            append(field.name)
            if (field.args.isNotEmpty()) {
                append("(")
                append(field.args.joinToString(", ") { "${it.name}: ${it.typeRef.namedType()}${if (it.typeRef.isNonNull()) "!" else ""}" })
                append(")")
            }
            append(": ").append(field.typeRef.namedType())
        }
        return DefaultMutableTreeNode(sig)
    }
}
