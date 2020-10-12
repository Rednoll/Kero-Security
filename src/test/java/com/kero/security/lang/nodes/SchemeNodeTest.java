package com.kero.security.lang.nodes;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.lang.tokens.DefaultAccessToken;

public class SchemeNodeTest {

	@Test
	public void interpret() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
		
		SchemeNode node = new SchemeNode("TestClass", DefaultAccessToken.DENY.toNode(), Collections.emptyList());
	
		node.interpret(agent);
		
		assertEquals(scheme.getDefaultAccess(), Access.DENY);
		assertEquals(scheme.getLocalProperties().size(), 0);
	}
	
	public static class TestClass {}
}
