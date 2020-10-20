package com.kero.security.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.tokens.NameToken;

public class NameLexemTest {

	@Test
	public void match() {
		
		NameLexem lexem = new NameLexem();
		
		assertTrue(lexem.isMatch("name"));
		assertFalse(lexem.isMatch("0name"));
		assertFalse(lexem.isMatch(""));
	}
	
	@Test
	public void tokenize() {
		
		NameLexem lexem = new NameLexem();
		
		NameToken token = lexem.tokenize("name");
	
		assertEquals(token.getRaw(), "name");
	}
}
