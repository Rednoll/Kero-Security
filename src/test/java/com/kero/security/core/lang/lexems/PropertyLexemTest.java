package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class PropertyLexemTest {

	@Test
	public void test() {
		
		PropertyLexem lexem = new PropertyLexem();
		
		assertTrue(lexem.isMatch("name(G):"));
		assertTrue(lexem.isMatch("name:"));
		assertTrue(lexem.isMatch("name(F)"));
		
		assertFalse(lexem.isMatch("name():"));
		assertFalse(lexem.isMatch("0name(G):"));
	}
}
