package com.redcell.gqlanalyzer.schema

/**
 * Typed, deserialization-agnostic view of a GraphQL schema. Produced either by
 * [IntrospectionParser] (full introspection) or, partially, by
 * [SchemaReconstructor] (field-suggestion harvesting when introspection is off).
 */
data class SchemaModel(
    val queryTypeName: String?,
    val mutationTypeName: String?,
    val subscriptionTypeName: String?,
    val types: List<GqlType>,
    /** True when this model came from error-message reconstruction, not introspection. */
    val reconstructed: Boolean = false,
) {
    val typesByName: Map<String, GqlType> = types.associateBy { it.name }

    fun type(name: String?): GqlType? = name?.let { typesByName[it] }
    fun queryType(): GqlType? = type(queryTypeName)
    fun mutationType(): GqlType? = type(mutationTypeName)

    /** Root query fields (entry points). */
    fun queries(): List<GqlField> = queryType()?.fields ?: emptyList()

    /** Root mutation fields. */
    fun mutations(): List<GqlField> = mutationType()?.fields ?: emptyList()

    /** Object/interface types that expose an argument named like an object id (id/uuid/_id). */
    fun idBearingFields(): List<Pair<GqlType, GqlField>> =
        types.filter { it.kind == "OBJECT" || it.kind == "INTERFACE" }
            .flatMap { t -> t.fields.map { t to it } }
            .filter { (_, f) -> f.args.any { it.name.lowercase() in ID_ARG_NAMES } }

    companion object {
        val ID_ARG_NAMES = setOf("id", "_id", "uuid", "guid", "userid", "user_id")
    }
}

data class GqlType(
    val name: String,
    val kind: String, // OBJECT, SCALAR, ENUM, INPUT_OBJECT, INTERFACE, UNION
    val fields: List<GqlField> = emptyList(),
    val inputFields: List<GqlInputValue> = emptyList(),
    val enumValues: List<String> = emptyList(),
    val description: String? = null,
)

data class GqlField(
    val name: String,
    val typeRef: GqlTypeRef,
    val args: List<GqlInputValue> = emptyList(),
    val description: String? = null,
)

data class GqlInputValue(
    val name: String,
    val typeRef: GqlTypeRef,
    val defaultValue: String? = null,
    val description: String? = null,
)

/** A possibly-wrapped type reference (NON_NULL / LIST around a named type). */
data class GqlTypeRef(
    val kind: String,
    val name: String? = null,
    val ofType: GqlTypeRef? = null,
) {
    /** The underlying named type, unwrapping NON_NULL/LIST wrappers. */
    fun namedType(): String? = name ?: ofType?.namedType()

    fun isNonNull(): Boolean = kind == "NON_NULL"
}
