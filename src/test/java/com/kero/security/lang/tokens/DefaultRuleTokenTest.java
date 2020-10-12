package com.kero.security.lang.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.nodes.DefaultAccessNode;

public class DefaultRuleTokenTest {

	@Test
	public void toNode() {
		
		DefaultRuleToken grant = DefaultRuleToken.GRANT;
		assertEquals(grant.toNode(), DefaultAccessNode.GRANT);
		
		DefaultRuleToken deny = DefaultRuleToken.DENY;
		assertEquals(deny.toNode(), DefaultAccessNode.DENY);
		
		DefaultRuleToken empty = DefaultRuleToken.EMPTY;
		assertEquals(empty.toNode(), DefaultAccessNode.EMPTY);
	}
}
