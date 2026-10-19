package com.redcell.gqlanalyzer.transport

import burp.api.montoya.http.message.HttpRequestResponse
import io.mockk.mockk
import kotlin.test.Test
import kotlin.test.assertTrue

class OobTest {

    /** Collaborator that is available and mints ids but whose payloads never fire. */
    private class NeverFires : OobClient {
        private var n = 0
        override fun available() = true
        override fun generate(): OobPayload = OobPayload("h${n}.oast.example", "id${n++}")
        override fun firedIds(): Set<String> = emptySet()
    }

    @Test
    fun `run returns promptly and preserves the interrupt flag when interrupted during polling`() {
        val oob = NeverFires()
        val target = OobScanner.Target("Query.x(a)") { _ -> mockk<HttpRequestResponse>(relaxed = true) }
        val scanner = OobScanner(oob, pollAttempts = 10, pollDelayMs = 60_000) // would block ~10 minutes

        Thread.currentThread().interrupt() // unload/cancel arrives before the first sleep
        val fired = scanner.run(listOf(target))
        val wasInterrupted = Thread.interrupted() // read-and-clear

        assertTrue(fired.isEmpty())      // nothing fired, and we didn't wait out the poll
        assertTrue(wasInterrupted)       // interrupt flag restored for the caller to observe
    }
}
