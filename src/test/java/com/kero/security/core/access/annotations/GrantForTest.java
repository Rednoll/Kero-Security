package com.kero.security.core.access.annotations;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import com.kero.security.core.agent.KeroAccessAgent;
import com.kero.security.core.agent.KeroAccessAgentFactoryImpl;
import com.kero.security.core.scheme.AccessScheme;
import com.kero.security.core.scheme.configurator.AnnotationAccessSchemeConfigurator;

public class GrantForTest {

	@Test
	public void test() {
		
		KeroAccessAgent agent = new KeroAccessAgentFactoryImpl().create();
			agent.addConfigurator(new AnnotationAccessSchemeConfigurator(agent));
			
		AccessScheme scheme = agent.getOrCreateScheme(TestClass.class);
	
		assertTrue(scheme.getOrCreateLocalProperty("name").getGrantRoles().contains(agent.getRole("OWNER")));
	}
	
	public static class TestClass {
		
		@GrantFor("OWNER")
		private String name;
		
		public String getName() {
			
			return this.name;
		}
	}
}
