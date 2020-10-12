package com.kero.security.lang.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.DefaultAccessNode;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.tokens.DefaultAccessToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;

public class SchemeParserTest {

	@Test
	public void isMatch() {
		
		SchemeParser parser = new SchemeParser();
		
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.SCHEME);
			seq.add(new NameToken("TestScheme"));
		
		assertTrue(parser.isMatch(seq));
		
		seq = new TokenSequence();
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(KeyWordToken.SCHEME);
			
		assertFalse(parser.isMatch(seq));
		
		seq = new TokenSequence();
		assertFalse(parser.isMatch(seq));
	}
	
	@Test
	public void parse() {
		
		SchemeParser parser = new SchemeParser();
		
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.SCHEME);
			seq.add(new NameToken("TestScheme"));
			seq.add(DefaultAccessToken.DENY);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(KeyWordToken.CLOSE_BLOCK);
			
		SchemeNode schemeNode = parser.parse(seq);
		
		assertEquals(schemeNode.getName(), "TestScheme");
		assertEquals(schemeNode.getDefaultAccess(), DefaultAccessNode.DENY);
	}
}
