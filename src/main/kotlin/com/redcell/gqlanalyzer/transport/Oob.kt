package com.redcell.gqlanalyzer.transport

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse

/** A minted out-of-band payload: the hostname to inject and the id to correlate hits by. */
data class OobPayload(val hostname: String, val id: String)

/**
 * Abstraction over an out-of-band interaction service (Burp Collaborator). Kept as an
 * interface so checks are unit-testable without the Montoya collaborator runtime.
 */
interface OobClient {
    fun available(): Boolean
    fun generate(): OobPayload

    /** Interaction ids that have fired so far (DNS/HTTP/etc.). */
    fun firedIds(): Set<String>
}

/** Montoya-backed [OobClient] wrapping a Burp Collaborator client. */
class BurpOobClient(private val api: MontoyaApi) : OobClient {
    private val client by lazy { runCatching { api.collaborator().createClient() }.getOrNull() }

    override fun available(): Boolean = client != null

    override fun generate(): OobPayload {
        val p = client!!.generatePayload()
        return OobPayload(hostname = p.toString(), id = p.id().toString())
    }

    override fun firedIds(): Set<String> =
        runCatching { client!!.getAllInteractions().map { it.id().toString() }.toSet() }.getOrDefault(emptySet())
}

/**
 * Drives OOB confirmation: mints a payload per target, sends each (via the target's
 * sender), then polls for interactions and reports which targets fired. Poll cadence is
 * injectable so tests run instantly.
 */
class OobScanner(
    private val oob: OobClient,
    private val pollAttempts: Int = 6,
    private val pollDelayMs: Long = 2000,
) {
    /** A thing to probe: a human label + a sender that injects the given OOB hostname and returns evidence. */
    class Target(val label: String, val send: (hostname: String) -> HttpRequestResponse)

    /** label -> evidence for every target whose payload received an interaction. */
    fun run(targets: List<Target>): Map<String, HttpRequestResponse> {
        if (!oob.available() || targets.isEmpty()) return emptyMap()

        val idToLabel = LinkedHashMap<String, String>()
        val idToEvidence = LinkedHashMap<String, HttpRequestResponse>()
        for (t in targets) {
            val p = oob.generate()
            idToLabel[p.id] = t.label
            idToEvidence[p.id] = t.send(p.hostname)
        }

        val wanted = idToLabel.keys
        var hits = emptySet<String>()
        repeat(pollAttempts) { attempt ->
            hits = oob.firedIds().intersect(wanted)
            if (hits.size == wanted.size) return@repeat
            if (attempt < pollAttempts - 1 && pollDelayMs > 0) {
                runCatching { Thread.sleep(pollDelayMs) }
            }
        }
        hits = oob.firedIds().intersect(wanted)
        return hits.associate { idToLabel[it]!! to idToEvidence[it]!! }
    }
}
