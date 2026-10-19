package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import io.mockk.every
import io.mockk.mockk
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WorkersTest {

    private fun apiWith(logging: Logging): MontoyaApi =
        mockk<MontoyaApi>(relaxed = true).also { every { it.logging() } returns logging }

    @Test
    fun `submit runs the block on a background thread`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val latch = CountDownLatch(1)
        Workers().submit(api, "t") { latch.countDown() }
        assertTrue(latch.await(2, TimeUnit.SECONDS))
    }

    @Test
    fun `an uncaught exception is written to the extension error stream, not propagated`() {
        val logging = mockk<Logging>(relaxed = true)
        val latch = CountDownLatch(1)
        every { logging.logToError(any<String>()) } answers { latch.countDown() }

        Workers().submit(apiWith(logging), "retest") { throw RuntimeException("boom-xyz") }

        assertTrue(latch.await(2, TimeUnit.SECONDS)) // logged, and the worker did not crash the test
    }

    @Test
    fun `shutdown deactivates and drops further work`() {
        val api = mockk<MontoyaApi>(relaxed = true)
        val w = Workers()
        assertTrue(w.active)
        w.shutdown()
        assertFalse(w.active)

        // A submission after shutdown is ignored (no thread started, no exception).
        var ran = false
        w.submit(api, "late") { ran = true }
        Thread.sleep(100)
        assertFalse(ran)
    }
}
