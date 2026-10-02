package com.redcell.gqlanalyzer.model

import com.redcell.gqlanalyzer.schema.GqlField

/** The three GraphQL root operation kinds. */
enum class OperationKind { QUERY, MUTATION, SUBSCRIPTION }

/** Outcome of probing a single operation during a crawl/scan. */
enum class OperationStatus {
    /** Not yet probed (default in the operations table). */
    NOT_RUN,

    /** Returned non-null data for the field. */
    RESOLVED,

    /** 2xx with no error but data was null/empty. */
    EMPTY,

    /** Rejected by an authorization/authentication error. */
    DENIED,

    /** Any other error (validation, server error, transport). */
    ERROR,
}

/**
 * One enumerated, individually-testable root operation — a single Query, Mutation,
 * or Subscription field — the unit the crawler/scanner works over (like an item in
 * a Burp API scan).
 */
data class Operation(
    val kind: OperationKind,
    val field: GqlField,
    val parentTypeName: String,
) {
    /** Stable identifier, e.g. "QUERY.user" — used as the per-operation finding location suffix. */
    val name: String get() = "$kind.${this.field.name}"

    /** True if the field has at least one required (NON_NULL) argument. */
    val requiresArgs: Boolean get() = this.field.args.any { it.typeRef.isNonNull() }
}
