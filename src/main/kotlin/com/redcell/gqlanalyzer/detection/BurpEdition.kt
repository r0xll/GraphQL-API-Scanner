package com.redcell.gqlanalyzer.detection

/**
 * Burp edition detection. Burp Scanner (passive scan checks, site-map issues) and
 * Collaborator are Professional-only; on Community those APIs are inert at best and may
 * throw. The extension reads `api.burpSuite().version().name()` and uses this to skip the
 * Professional-only wiring on Community — the active, HTTP-driven scanner still works there.
 */
object BurpEdition {

    /**
     * True when [versionName] (from `Version.name()`) is a Professional/DAST build — i.e. the
     * Scanner/Issues and Collaborator features are available. Community editions report a name
     * containing "Community". Unknown/blank names default to Professional so Pro users never
     * silently lose the passive issue; the call sites still wrap the APIs defensively.
     */
    fun isProfessional(versionName: String?): Boolean {
        val name = versionName?.trim().orEmpty()
        if (name.isEmpty()) return true // undetectable — assume Pro; call sites are runCatching-guarded
        return !name.contains("Community", ignoreCase = true)
    }
}
