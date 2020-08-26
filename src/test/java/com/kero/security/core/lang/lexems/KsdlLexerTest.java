package com.kero.security.core.lang.lexems;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.kero.security.core.lang.KsdlLexer;
import com.kero.security.core.lang.tokens.KsdlToken;

public class KsdlLexerTest {

	@Test
	public void test() {
		
		KsdlLexer lexer = new KsdlLexer();
		
		List<KsdlToken> tokens = lexer.tokenize("protect KeroHealthTest(D): protectName(D): +OWNER -COMMON");
	
		for(KsdlToken token : tokens) {
			
			System.out.println(token);
		}
	}
}
