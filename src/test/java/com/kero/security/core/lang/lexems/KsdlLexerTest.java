package com.kero.security.core.lang.lexems;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.kero.security.core.TestObject;
import com.kero.security.core.lang.KsdlLexer;
import com.kero.security.core.lang.nodes.TypeNode;
import com.kero.security.core.lang.parsers.TypeParser;
import com.kero.security.core.lang.tokens.KsdlToken;
import com.kero.security.core.managers.KeroAccessManager;
import com.kero.security.core.managers.KeroAccessManagerImpl;

public class KsdlLexerTest {

	@Test
	public void test() {
		
		KeroAccessManager manager = new KeroAccessManagerImpl();
		
		KsdlLexer lexer = new KsdlLexer();
		
		List<KsdlToken> tokens = lexer.tokenize("protect TestObject(D): text(D): +OWNER -COMMON");
		
		TypeParser parser = new TypeParser();
	
		TypeNode node = parser.parse(manager, tokens);
	
		for(KsdlToken token : tokens) {
			
			System.out.println(token);
		}
		
		node.interpret(manager);
		
		manager.protect(new TestObject(), "OWNER").getText();
	}
}
