package com.redcell.gqlanalyzer.detection

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BurpEditionTest {

    @Test
    fun `professional and DAST builds are treated as professional`() {
        assertTrue(BurpEdition.isProfessional("Burp Suite Professional"))
        assertTrue(BurpEdition.isProfessional("Burp Suite Enterprise Edition"))
        assertTrue(BurpEdition.isProfessional("Burp Suite DAST"))
    }

    @Test
    fun `community builds are not professional`() {
        assertFalse(BurpEdition.isProfessional("Burp Suite Community Edition"))
        assertFalse(BurpEdition.isProfessional("burp suite community edition")) // case-insensitive
    }

    @Test
    fun `unknown or blank name defaults to professional (call sites stay guarded)`() {
        assertTrue(BurpEdition.isProfessional(null))
        assertTrue(BurpEdition.isProfessional(""))
        assertTrue(BurpEdition.isProfessional("   "))
    }
}
