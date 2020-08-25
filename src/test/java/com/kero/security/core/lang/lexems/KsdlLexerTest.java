package com.kero.security.core.lang.lexems;

import org.junit.jupiter.api.Test;

import com.kero.security.core.lang.KsdlLexer;

public class KsdlLexerTest {

	@Test
	public void test() {
		
		KsdlLexer lexer = new KsdlLexer();
		
		lexer.tokenize("");
	}
}
