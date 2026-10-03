package com.redcell.gqlanalyzer.transport

import com.redcell.gqlanalyzer.checks.Heuristics
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ScalarValuesTest {

    @Test
    fun `table hits for common custom scalars`() {
        assertEquals("\"2020-01-01T00:00:00Z\"", ScalarValues.sampleFor("DateTime"))
        assertEquals("\"2020-01-01\"", ScalarValues.sampleFor("Date"))
        assertTrue(ScalarValues.sampleFor("UUID")!!.contains("-"))
        assertEquals("\"test@example.com\"", ScalarValues.sampleFor("EmailAddress"))
        assertEquals("\"https://example.com\"", ScalarValues.sampleFor("URL"))
        assertNull(ScalarValues.sampleFor("ProductSerialNumber"))
    }

    // The three real-world errors from the field.

    @Test
    fun `DateTime synthesizes an ISO datetime from the table`() {
        val msg = """Expected value of type "DateTime!", found "test"; DateTime cannot represent an invalid date-time-string test."""
        assertEquals("\"2020-01-01T00:00:00Z\"", ScalarValues.synthesize("DateTime", msg))
    }

    @Test
    fun `ProductSerialNumber mines exactly-16-digit constraint from the error`() {
        val msg = """Expected value of type "ProductSerialNumber!", found "test"; Product serial number must either be a string that is exactly 16 characters long where each character is parsable as an integer, or an alpha-numeric string that beings with KS_."""
        assertEquals("\"0000000000000000\"", ScalarValues.synthesize("ProductSerialNumber", msg))
    }

    @Test
    fun `AgeCategory falls back to a date from the error wording`() {
        val msg = """Expected value of type "AgeCategory!", found "test"; Date cannot represent invalid value: "test"."""
        assertEquals("\"2020-01-01\"", ScalarValues.synthesize("AgeCategory", msg))
    }

    @Test
    fun `begins-with constraint builds a prefixed value`() {
        val v = ScalarValues.synthesize("Token", "value must begin with KS_")!!
        assertTrue(v.startsWith("\"KS_"))
    }

    @Test
    fun `unknown scalar with no usable hint yields null`() {
        assertNull(ScalarValues.synthesize("Weird", "something went wrong"))
    }

    @Test
    fun `heuristics detect coercion and extract the type name`() {
        val msg = """Expected value of type "DateTime!", found "test"; DateTime cannot represent an invalid date-time-string."""
        assertTrue(Heuristics.isInputCoercionError(msg))
        assertEquals("DateTime", Heuristics.coercionTypeName(msg))
        assertEquals("ProductSerialNumber", Heuristics.coercionTypeName("""Expected value of type "ProductSerialNumber!", found "test""""))
        assertTrue(!Heuristics.isInputCoercionError("""{"errors":[{"message":"Forbidden"}]}"""))
    }
}
