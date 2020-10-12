package com.kero.security.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class DefaultRuleLexemTest {

	@Test
	public void test() {
		
		DefaultRuleLexem lexem = new DefaultRuleLexem();
		
		assertTrue(lexem.isMatch("(G)"));
		assertTrue(lexem.isMatch("(D)"));
		assertFalse(lexem.isMatch("(C)"));
	}
}
