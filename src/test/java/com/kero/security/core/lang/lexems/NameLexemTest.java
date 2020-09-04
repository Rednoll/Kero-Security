package com.kero.security.core.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.lexems.NameLexem;

public class NameLexemTest {

	@Test
	public void test() {
		
		NameLexem lexem = new NameLexem();
		
		assertTrue(lexem.isMatch("name"));
		assertFalse(lexem.isMatch("0name"));
	}
}
