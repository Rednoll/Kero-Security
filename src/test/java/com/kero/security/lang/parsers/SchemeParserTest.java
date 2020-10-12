package com.kero.security.lang.parsers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.DefaultAccessNode;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.nodes.metaline.PropagationMetaline;
import com.kero.security.lang.tokens.DefaultRuleToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.lang.tokens.RoleToken;

public class SchemeParserTest {

	@Test
	public void parse() {
		
		SchemeParser parser = new SchemeParser();
		
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.SCHEME);
			seq.add(new NameToken("TestScheme"));
			seq.add(DefaultRuleToken.DENY);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(new NameToken("text"));
			seq.add(DefaultRuleToken.GRANT);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(new RoleToken(true, "OWNER"));
			seq.add(new RoleToken(false, "FRIEND"));
			seq.add(KeyWordToken.CLOSE_BLOCK);
			seq.add(KeyWordToken.METALINE);
			seq.add(new NameToken("propagation"));
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(new NameToken("OWNER"));
			seq.add(KeyWordToken.FORWARD_DIRECTION);
			seq.add(new NameToken("FRIEND"));
			seq.add(KeyWordToken.CLOSE_BLOCK);
			seq.add(KeyWordToken.CLOSE_BLOCK);
			
		SchemeNode schemeNode = parser.parse(seq);
		
		assertEquals(schemeNode.getName(), "TestScheme");
		assertEquals(schemeNode.getDefaultAccess(), DefaultAccessNode.DENY);
		
		PropertyNode propNode = schemeNode.getProperties().get(0);
		
		assertEquals(propNode.getName(), "text");
		assertEquals(propNode.getDefaultAccess(), DefaultAccessNode.GRANT);
		assertTrue(propNode.getGrantRoles().contains("OWNER"));
		assertTrue(propNode.getDenyRoles().contains("FRIEND"));
		
		PropagationMetaline metaline = (PropagationMetaline) propNode.getMetalines().get(0);
		
		assertEquals(metaline.getPropagationMap().get("OWNER"), "FRIEND");
	}
}
