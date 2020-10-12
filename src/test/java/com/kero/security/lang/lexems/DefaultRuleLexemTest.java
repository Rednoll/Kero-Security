package com.kero.security.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.tokens.DefaultAccessToken;

public class DefaultRuleLexemTest {

	@Test
	public void match() {
		
		DefaultRuleLexem lexem = new DefaultRuleLexem();
		
		assertTrue(lexem.isMatch("(G)"));
		assertTrue(lexem.isMatch("(D)"));
		assertFalse(lexem.isMatch("(C)"));
	}
	
	@Test
	public void tokenize() {
		
		DefaultRuleLexem lexem = new DefaultRuleLexem();
		
		DefaultAccessToken grant = lexem.tokenize("(G)");
		assertEquals(grant, DefaultAccessToken.GRANT);
		assertEquals(grant.getDefaultAccessible(), true);
		
		DefaultAccessToken deny = lexem.tokenize("(D)");
		assertEquals(deny, DefaultAccessToken.DENY);
		assertEquals(deny.getDefaultAccessible(), false);
	}
}
