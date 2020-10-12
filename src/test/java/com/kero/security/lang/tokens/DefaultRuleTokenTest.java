package com.kero.security.lang.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.kero.security.lang.nodes.DefaultAccessNode;

public class DefaultRuleTokenTest {

	@Test
	public void toNode() {
		
		DefaultAccessToken grant = DefaultAccessToken.GRANT;
		assertEquals(grant.toNode(), DefaultAccessNode.GRANT);
		
		DefaultAccessToken deny = DefaultAccessToken.DENY;
		assertEquals(deny.toNode(), DefaultAccessNode.DENY);
		
		DefaultAccessToken empty = DefaultAccessToken.EMPTY;
		assertEquals(empty.toNode(), DefaultAccessNode.EMPTY);
	}
}
