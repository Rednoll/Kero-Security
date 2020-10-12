package com.kero.security.lang.nodes;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.kero.security.core.access.Access;
import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.property.Property;
import com.kero.security.core.scheme.AccessScheme;

public class PropertyNodeTest {

	@Test
	public void interpret() {
		
		Set<String> grantRoles = new HashSet<>();
			grantRoles.add("OWNER");
		
		Set<String> denyRoles = new HashSet<>();
			denyRoles.add("ANY");
		
		PropertyNode propertyNode = new PropertyNode("text", DefaultAccessNode.GRANT, grantRoles, denyRoles, Collections.emptyList());
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
		
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		propertyNode.interpret(scheme);
		
		Property property = scheme.getLocalProperty("text");
	
		assertEquals(property.getDefaultAccess(), Access.GRANT);
		assertTrue(property.getGrantRoles().contains(agent.getRole("OWNER")));
		assertTrue(property.getDenyRoles().contains(agent.getRole("ANY")));
	}
	
	public static class TestClass {}
}
