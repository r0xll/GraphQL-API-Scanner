package com.redcell.gqlanalyzer.detection

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction

/**
 * Passive detection hook. Highlights and annotates any proxied response whose
 * request/response fingerprints as GraphQL. Sends nothing; purely observational.
 */
class EndpointTagger(private val api: MontoyaApi) : HttpHandler {

    /** URLs already tagged, so the extension log stays quiet on repeats (bounded, see [SEEN_CAP]). */
    private val seen = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()

    private companion object {
        const val SEEN_CAP = 5000
    }

    override fun handleHttpRequestToBeSent(request: HttpRequestToBeSent): RequestToBeSentAction =
        RequestToBeSentAction.continueWith(request)

    override fun handleHttpResponseReceived(response: HttpResponseReceived): ResponseReceivedAction {
        val request = response.initiatingRequest()
        val detection = GraphQLFingerprint.classify(
            path = request.path(),
            requestBody = request.bodyToString(),
            responseBody = response.bodyToString(),
        )
        if (!detection.isGraphQL) return ResponseReceivedAction.continueWith(response)

        val url = runCatching { request.url() }.getOrDefault(request.path())
        // Bound the de-dupe set so a very long session can't grow it without limit (rule 7).
        if (seen.size > SEEN_CAP) seen.clear()
        if (seen.add(url)) {
            api.logging().logToOutput("GraphQL endpoint detected: $url — ${detection.reasons.joinToString("; ")}")
        }
        val annotations = response.annotations()
            .withHighlightColor(HighlightColor.CYAN)
            .withNotes("GraphQL (passive): ${detection.reasons.joinToString("; ")}")
        return ResponseReceivedAction.continueWith(response, annotations)
    }
}
