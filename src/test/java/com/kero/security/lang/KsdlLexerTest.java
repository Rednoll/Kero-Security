package com.kero.security.lang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.tokens.DefaultAccessToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.lang.tokens.RoleToken;

public class KsdlLexerTest {

	@Test
	public void test() {
		
		String data =
			"scheme TestScheme(D) {\n"
			+ "text(G): -OWNER \n"
			+ "- propagation: FRIEND -> ANY \n"
			+ "}";
		
		KsdlLexer lexer = KsdlLexer.getInstance();
		
		TokenSequence seq = lexer.tokenize(data);
		
		assertEquals(seq.get(0), KeyWordToken.SCHEME);
		assertTrue(seq.get(1) instanceof NameToken);
		assertEquals(seq.get(2), DefaultAccessToken.DENY);
		assertEquals(seq.get(3), KeyWordToken.OPEN_BLOCK);
		assertTrue(seq.get(4) instanceof NameToken);
		assertEquals(seq.get(5), DefaultAccessToken.GRANT);
		assertEquals(seq.get(6), KeyWordToken.OPEN_BLOCK);
		assertTrue(seq.get(7) instanceof RoleToken);
		assertEquals(seq.get(8), KeyWordToken.CLOSE_BLOCK);
		assertEquals(seq.get(9), KeyWordToken.METALINE);
		assertTrue(seq.get(10) instanceof NameToken);
		assertEquals(seq.get(11), KeyWordToken.OPEN_BLOCK);
		assertTrue(seq.get(12) instanceof NameToken);
		assertEquals(seq.get(13), KeyWordToken.FORWARD_DIRECTION);
		assertTrue(seq.get(14) instanceof NameToken);
		assertEquals(seq.get(15), KeyWordToken.CLOSE_BLOCK);
		assertEquals(seq.get(16), KeyWordToken.CLOSE_BLOCK);
	}
}
