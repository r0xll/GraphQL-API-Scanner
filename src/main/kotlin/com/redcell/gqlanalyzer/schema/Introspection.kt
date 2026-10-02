package com.redcell.gqlanalyzer.schema

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/**
 * Standard GraphQL introspection query and the DTOs + parser for its response.
 * Parsing is pure (no Montoya, no I/O) so it is unit-testable against fixtures.
 */
object Introspection {

    /** Minimal-but-complete introspection query (2-level ofType nesting is plenty for named-type resolution). */
    val QUERY: String = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              kind
              name
              description
              fields(includeDeprecated: true) {
                name
                description
                args { name description defaultValue type { ...TypeRef } }
                type { ...TypeRef }
              }
              inputFields { name description defaultValue type { ...TypeRef } }
              enumValues(includeDeprecated: true) { name }
            }
          }
        }
        fragment TypeRef on __Type {
          kind name
          ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }
        }
    """.trimIndent()
}

@Serializable
data class IntrospectionResponse(
    val data: IntrospectionData? = null,
    val errors: List<GqlError> = emptyList(),
)

@Serializable
data class IntrospectionData(
    @SerialName("__schema") val schema: IntrospectionSchema? = null,
)

@Serializable
data class IntrospectionSchema(
    val queryType: NamedRef? = null,
    val mutationType: NamedRef? = null,
    val subscriptionType: NamedRef? = null,
    val types: List<FullTypeDef> = emptyList(),
)

@Serializable
data class NamedRef(val name: String? = null)

@Serializable
data class FullTypeDef(
    val kind: String? = null,
    val name: String? = null,
    val description: String? = null,
    val fields: List<FieldDef>? = null,
    val inputFields: List<InputValueDef>? = null,
    val enumValues: List<EnumValueDef>? = null,
)

@Serializable
data class FieldDef(
    val name: String,
    val description: String? = null,
    val args: List<InputValueDef> = emptyList(),
    val type: TypeRefDef,
)

@Serializable
data class InputValueDef(
    val name: String,
    val description: String? = null,
    val type: TypeRefDef,
    val defaultValue: String? = null,
)

@Serializable
data class EnumValueDef(val name: String)

@Serializable
data class TypeRefDef(
    val kind: String? = null,
    val name: String? = null,
    val ofType: TypeRefDef? = null,
)

@Serializable
data class GqlError(
    val message: String = "",
)

/** Pure mapper: introspection JSON -> [SchemaModel]. Returns null when there is no `__schema`. */
object IntrospectionParser {

    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        coerceInputValues = true
    }

    fun parse(raw: String): SchemaModel? {
        val resp = runCatching { json.decodeFromString<IntrospectionResponse>(raw) }.getOrNull() ?: return null
        val schema = resp.data?.schema ?: return null
        val types = schema.types.mapNotNull { it.toModel() }
        return SchemaModel(
            queryTypeName = schema.queryType?.name,
            mutationTypeName = schema.mutationType?.name,
            subscriptionTypeName = schema.subscriptionType?.name,
            types = types,
        )
    }

    private fun FullTypeDef.toModel(): GqlType? {
        val n = name ?: return null
        return GqlType(
            name = n,
            kind = kind ?: "",
            fields = fields?.map { it.toModel() } ?: emptyList(),
            inputFields = inputFields?.map { it.toModel() } ?: emptyList(),
            enumValues = enumValues?.map { it.name } ?: emptyList(),
            description = description,
        )
    }

    private fun FieldDef.toModel() = GqlField(
        name = name,
        typeRef = type.toModel(),
        args = args.map { it.toModel() },
        description = description,
    )

    private fun InputValueDef.toModel() = GqlInputValue(
        name = name,
        typeRef = type.toModel(),
        defaultValue = defaultValue,
        description = description,
    )

    private fun TypeRefDef.toModel(): GqlTypeRef =
        GqlTypeRef(kind = kind ?: "", name = name, ofType = ofType?.toModel())
}
