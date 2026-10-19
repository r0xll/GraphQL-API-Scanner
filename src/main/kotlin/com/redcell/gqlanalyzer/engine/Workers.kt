package com.redcell.gqlanalyzer.engine

import burp.api.montoya.MontoyaApi
import java.util.concurrent.Executors
import java.util.concurrent.ThreadFactory
import java.util.concurrent.atomic.AtomicInteger

/**
 * Owns every background thread the extension starts, so they can be terminated when the
 * extension unloads (BApp rule 4). Slow work (HTTP sends during enumerate/scan/re-test) runs
 * here off the Swing EDT (rule 3), and any uncaught exception is written to the extension
 * error stream rather than silently lost (rule 3's note — Burp does not report background
 * exceptions on its own).
 *
 * Register [shutdown] with `api.extension().registerUnloadingHandler { ... }` so an unload
 * interrupts in-flight workers; cooperatively-cancellable loops (the operation scan, the OOB
 * poll) observe the interrupt and stop promptly.
 */
class Workers {

    @Volatile
    var active: Boolean = true
        private set

    private val counter = AtomicInteger(0)

    private val executor = Executors.newCachedThreadPool(
        object : ThreadFactory {
            override fun newThread(r: Runnable): Thread =
                Thread(r, "gql-analyzer-worker-${counter.incrementAndGet()}").apply { isDaemon = true }
        },
    )

    /**
     * Run [block] on a background thread. Uncaught throwables are logged to the extension error
     * stream with their stack trace; they never propagate out of the worker. Rejected submissions
     * (after [shutdown]) are ignored.
     */
    fun submit(api: MontoyaApi, name: String, block: () -> Unit) {
        if (!active) return
        runCatching {
            executor.submit {
                try {
                    block()
                } catch (t: InterruptedException) {
                    Thread.currentThread().interrupt() // unload/cancel — stop quietly
                } catch (t: Throwable) {
                    runCatching {
                        api.logging().logToError("[$name] background task failed:\n" + t.stackTraceToString())
                    }
                }
            }
        }
    }

    /** Stop accepting work and interrupt in-flight workers. Idempotent; safe from the unload handler. */
    fun shutdown() {
        active = false
        runCatching { executor.shutdownNow() }
    }
}
