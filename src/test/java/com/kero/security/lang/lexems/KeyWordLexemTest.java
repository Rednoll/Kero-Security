package com.kero.security.lang.lexems;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.tokens.KeyWordToken;

public class KeyWordLexemTest {

	@Test
	public void match() {
		
		assertTrue(KeyWordLexem.SCHEME.isMatch("scheme"));
		assertFalse(KeyWordLexem.SCHEME.isMatch("schasdase"));
		
		assertTrue(KeyWordLexem.METALINE.isMatch("-"));
		assertFalse(KeyWordLexem.METALINE.isMatch("schasdase"));
		
		assertTrue(KeyWordLexem.FORWARD_DIRECTION.isMatch("->"));
		assertFalse(KeyWordLexem.FORWARD_DIRECTION.isMatch("schasdase"));

		assertTrue(KeyWordLexem.OPEN_BLOCK.isMatch("{"));
		assertFalse(KeyWordLexem.OPEN_BLOCK.isMatch("schasdase"));
		
		assertTrue(KeyWordLexem.CLOSE_BLOCK.isMatch("}"));
		assertFalse(KeyWordLexem.CLOSE_BLOCK.isMatch("schasdase"));
		
		assertTrue(KeyWordLexem.OPEN_SHORT_BLOCK.isMatch(":"));
		assertFalse(KeyWordLexem.OPEN_SHORT_BLOCK.isMatch("schasdase"));
		
		assertTrue(KeyWordLexem.CLOSE_SHORT_BLOCK.isMatch("\n"));
		assertFalse(KeyWordLexem.CLOSE_SHORT_BLOCK.isMatch("schasdase"));
	}
	
	@Test
	public void tokenize() {
		
		KeyWordToken scheme = KeyWordLexem.SCHEME.tokenize("scheme");
		assertEquals(scheme, KeyWordToken.SCHEME);
		
		KeyWordToken metaline = KeyWordLexem.METALINE.tokenize("-");
		assertEquals(metaline, KeyWordToken.METALINE);
		
		KeyWordToken forwardDirection = KeyWordLexem.FORWARD_DIRECTION.tokenize("->");
		assertEquals(forwardDirection, KeyWordToken.FORWARD_DIRECTION);
		
		KeyWordToken openBlock = KeyWordLexem.OPEN_BLOCK.tokenize("{");
		assertEquals(openBlock, KeyWordToken.OPEN_BLOCK);
		
		KeyWordToken openShortBlock = KeyWordLexem.OPEN_SHORT_BLOCK.tokenize(":");
		assertEquals(openShortBlock, KeyWordToken.OPEN_BLOCK);
		
		KeyWordToken closeBlock = KeyWordLexem.CLOSE_BLOCK.tokenize("}");
		assertEquals(closeBlock, KeyWordToken.CLOSE_BLOCK);
		
		KeyWordToken closeShortBlock = KeyWordLexem.CLOSE_SHORT_BLOCK.tokenize("\n");
		assertEquals(closeShortBlock, KeyWordToken.CLOSE_BLOCK);
	}
}
