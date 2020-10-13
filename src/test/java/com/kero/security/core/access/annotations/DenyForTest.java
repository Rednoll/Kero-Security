package com.kero.security.core.access.annotations;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class DenyForTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
			
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertTrue(scheme.getOrCreateLocalProperty("name").getDenyRoles().contains(agent.getRole("FRIEND")));
	}
	
	public static class TestClass {
		
		@DenyFor("FRIEND")
		private String name;
	}
}
