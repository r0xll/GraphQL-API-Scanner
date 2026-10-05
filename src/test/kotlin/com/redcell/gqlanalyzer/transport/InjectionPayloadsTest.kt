package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.transport.InjectionPayloads.Technique
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class InjectionPayloadsTest {

    @Test
    fun `catalog covers every technique`() {
        val kinds = InjectionPayloads.inBand.map { it.technique }.toSet()
        assertTrue(Technique.ERROR in kinds)
        assertTrue(Technique.EVAL in kinds)
        assertTrue(Technique.FILE in kinds)
        assertTrue(Technique.TIME in kinds)
        assertTrue(Technique.BOOLEAN_TRUE in kinds)
        assertTrue(Technique.BOOLEAN_FALSE in kinds)
    }

    @Test
    fun `boolean technique is a single true-false pair`() {
        assertEquals(1, InjectionPayloads.inBand.count { it.technique == Technique.BOOLEAN_TRUE })
        assertEquals(1, InjectionPayloads.inBand.count { it.technique == Technique.BOOLEAN_FALSE })
    }

    @Test
    fun `SSTI payloads compute the distinctive 1337 product`() {
        val eval = InjectionPayloads.inBand.filter { it.technique == Technique.EVAL }
        assertTrue(eval.isNotEmpty())
        assertTrue(eval.all { it.value.contains("191") }) // 7*191 = 1337, rarer than 49
        assertEquals("1337", InjectionPayloads.SSTI_RESULT)
    }

    @Test
    fun `time payloads use a single short sleep`() {
        val time = InjectionPayloads.inBand.filter { it.technique == Technique.TIME }
        assertTrue(time.isNotEmpty())
        assertTrue(time.all { it.value.contains("5") }) // ~5s, not a flood
    }
}
