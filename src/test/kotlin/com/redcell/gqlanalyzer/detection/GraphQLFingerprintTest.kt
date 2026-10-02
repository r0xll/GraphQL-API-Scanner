package com.redcell.gqlanalyzer.detection

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GraphQLFingerprintTest {

    @Test
    fun `path matching covers common graphql ui routes`() {
        assertTrue(GraphQLFingerprint.pathLooksLikeGraphQL("/api/graphql"))
        assertTrue(GraphQLFingerprint.pathLooksLikeGraphQL("/graphiql"))
        assertTrue(GraphQLFingerprint.pathLooksLikeGraphQL("/v1/playground"))
        assertTrue(GraphQLFingerprint.pathLooksLikeGraphQL("/altair"))
        assertFalse(GraphQLFingerprint.pathLooksLikeGraphQL("/api/users"))
        assertFalse(GraphQLFingerprint.pathLooksLikeGraphQL("/graphqlish-blog"))
    }

    @Test
    fun `request body detection on single and batched operations`() {
        assertTrue(GraphQLFingerprint.bodyLooksLikeGraphQL("""{"query":"{ me { id } }"}"""))
        assertTrue(GraphQLFingerprint.bodyLooksLikeGraphQL("""{"operationName":"Q","query":"query Q{me}"}"""))
        assertTrue(GraphQLFingerprint.bodyLooksLikeGraphQL("""[{"query":"{a}"},{"query":"{b}"}]"""))
        assertFalse(GraphQLFingerprint.bodyLooksLikeGraphQL("""{"username":"x","password":"y"}"""))
        assertFalse(GraphQLFingerprint.bodyLooksLikeGraphQL(""))
        assertFalse(GraphQLFingerprint.bodyLooksLikeGraphQL("not json"))
    }

    @Test
    fun `response detection requires both data and errors`() {
        assertTrue(GraphQLFingerprint.responseHasDataAndErrors("""{"data":null,"errors":[{"message":"x"}]}"""))
        assertFalse(GraphQLFingerprint.responseHasDataAndErrors("""{"data":{"me":{"id":1}}}"""))
        assertFalse(GraphQLFingerprint.responseHasDataAndErrors("""{"ok":true}"""))
    }

    @Test
    fun `classify aggregates reasons`() {
        val d = GraphQLFingerprint.classify(
            path = "/graphql",
            requestBody = """{"query":"{me}"}""",
            responseBody = """{"data":null,"errors":[{"message":"x"}]}""",
        )
        assertTrue(d.isGraphQL)
        assertTrue(d.reasons.size == 3)
    }

    @Test
    fun `classify negative on plain REST`() {
        val d = GraphQLFingerprint.classify("/api/users", """{"name":"x"}""", """{"id":1}""")
        assertFalse(d.isGraphQL)
    }
}
