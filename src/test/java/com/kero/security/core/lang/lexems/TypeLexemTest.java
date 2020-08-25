package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class TypeLexemTest {
	
	@Test
	public void test() {
		
		TypeLexem lexem = new TypeLexem();
		
		assertTrue(lexem.isMatch("protect KeroSecurityTest(G):"));
		assertTrue(lexem.isMatch("protect KeroSecurityTest:"));
		assertTrue(lexem.isMatch("protect KeroSecurityTest(F)"));
		assertTrue(lexem.isMatch("protect KeroSecurityTest"));
		
		assertFalse(lexem.isMatch("KeroSecurityTest(G):"));
		assertFalse(lexem.isMatch("protect 0KeroSecurityTest(F):"));
		assertFalse(lexem.isMatch("protect KeroSecurityTest():"));
	}
}
