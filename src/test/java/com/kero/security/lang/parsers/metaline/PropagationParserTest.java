package com.kero.security.lang.parsers.metaline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.metaline.PropagationMetaline;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;

public class PropagationParserTest {

	@Test
	public void isMatch() {
		
		PropagationParser parser = new PropagationParser();
		
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.METALINE);
			seq.add(new NameToken("propagation"));
			seq.add(KeyWordToken.OPEN_BLOCK);
		
		assertTrue(parser.isMatch(seq));
	
		seq = new TokenSequence();
			seq.add(new NameToken("propagation"));
			seq.add(KeyWordToken.OPEN_BLOCK);
	
		assertFalse(parser.isMatch(seq));
		
		seq = new TokenSequence();
			seq.add(KeyWordToken.METALINE);
			seq.add(new NameToken("propagation1"));
			seq.add(KeyWordToken.OPEN_BLOCK);

		assertFalse(parser.isMatch(seq));
		
		seq = new TokenSequence();
			seq.add(KeyWordToken.METALINE);
			seq.add(new NameToken("propagation"));
	
		assertFalse(parser.isMatch(seq));
	}
	
	@Test
	public void parse() {
		
		PropagationParser parser = new PropagationParser();
	
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.METALINE);
			seq.add(new NameToken("propagation"));
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(new NameToken("OWNER"));
			seq.add(KeyWordToken.FORWARD_DIRECTION);
			seq.add(new NameToken("FRIEND"));
			seq.add(KeyWordToken.CLOSE_BLOCK);
		
		PropagationMetaline metaline = parser.parse(seq);
	
		assertEquals(metaline.getPropagationMap().get("OWNER"), "FRIEND");
	}
}
