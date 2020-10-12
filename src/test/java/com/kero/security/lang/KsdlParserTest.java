package com.kero.security.lang;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.collections.RootNodeList;
import com.kero.security.lang.collections.TokenSequence;
import com.kero.security.lang.nodes.PropertyNode;
import com.kero.security.lang.nodes.SchemeNode;
import com.kero.security.lang.nodes.metaline.MetalineNodeBase;
import com.kero.security.lang.nodes.metaline.PropagationMetaline;
import com.kero.security.lang.nodes.metaline.PropertyMetalineBase;
import com.kero.security.lang.tokens.DefaultAccessToken;
import com.kero.security.lang.tokens.KeyWordToken;
import com.kero.security.lang.tokens.NameToken;
import com.kero.security.lang.tokens.RoleToken;

public class KsdlParserTest {

	@Test
	public void parse() {
		
		KsdlParser parser = KsdlParser.getInstance();
	
		TokenSequence seq = new TokenSequence();
			seq.add(KeyWordToken.SCHEME);
			seq.add(new NameToken("TestScheme"));
			seq.add(DefaultAccessToken.DENY);
			seq.add(KeyWordToken.OPEN_BLOCK);
			seq.add(new NameToken("text"));
			seq.add(DefaultAccessToken.GRANT);
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
			
		RootNodeList roots = parser.parse(seq);
		
		assertEquals(roots.size(), 1);
		assertTrue(roots.get(0) instanceof SchemeNode);
		
		SchemeNode schemeNode = (SchemeNode) roots.get(0);
	
		List<PropertyNode> propertyNodes = schemeNode.getProperties();
	
		assertEquals(propertyNodes.size(), 1);
		
		PropertyNode propertyNode = propertyNodes.get(0);
		
		List<PropertyMetalineBase> metalineNodes = propertyNode.getMetalines();
		
		assertEquals(metalineNodes.size(), 1);
		assertTrue(metalineNodes.get(0) instanceof PropagationMetaline);
	}
}
