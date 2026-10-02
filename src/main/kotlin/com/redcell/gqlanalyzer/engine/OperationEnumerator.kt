package com.redcell.gqlanalyzer.engine

import com.redcell.gqlanalyzer.model.Operation
import com.redcell.gqlanalyzer.model.OperationKind
import com.redcell.gqlanalyzer.schema.SchemaModel

/** Turns a [SchemaModel] into the flat list of individually-testable root operations. */
object OperationEnumerator {

    fun enumerate(schema: SchemaModel): List<Operation> {
        val out = mutableListOf<Operation>()

        schema.queryType()?.let { q ->
            q.fields.forEach { out += Operation(OperationKind.QUERY, it, q.name) }
        }
        schema.mutationType()?.let { m ->
            m.fields.forEach { out += Operation(OperationKind.MUTATION, it, m.name) }
        }
        schema.type(schema.subscriptionTypeName)?.let { s ->
            s.fields.forEach { out += Operation(OperationKind.SUBSCRIPTION, it, s.name) }
        }
        return out
    }
}
