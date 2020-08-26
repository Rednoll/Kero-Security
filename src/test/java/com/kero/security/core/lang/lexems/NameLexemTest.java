package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

public class NameLexemTest {

	@Test
	public void test() {
		
		NameLexem lexem = new NameLexem();
		
		assertTrue(lexem.isMatch("name"));
		assertFalse(lexem.isMatch("0name"));
	}
}
